package com.shezguard.lint

import com.android.tools.lint.detector.api.JavaContext
import com.intellij.psi.PsiElement
import com.intellij.psi.PsiMethod
import com.intellij.psi.PsiParenthesizedExpression
import org.jetbrains.kotlin.lexer.KtTokens
import org.jetbrains.kotlin.psi.KtBinaryExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression
import org.jetbrains.kotlin.psi.KtParenthesizedExpression
import org.jetbrains.kotlin.psi.KtPostfixExpression
import org.jetbrains.kotlin.psi.KtProperty
import org.jetbrains.kotlin.psi.KtSafeQualifiedExpression
import org.jetbrains.uast.UBinaryExpression
import org.jetbrains.uast.UCallExpression
import org.jetbrains.uast.ULiteralExpression
import org.jetbrains.uast.UMethod
import org.jetbrains.uast.USimpleNameReferenceExpression
import org.jetbrains.uast.USuperExpression
import org.jetbrains.uast.UastBinaryOperator
import org.jetbrains.uast.UVariable
import org.jetbrains.uast.toUElement
import org.jetbrains.uast.visitor.AbstractUastVisitor

/**
 * Issue 4: the guard must run before `super.onCreate` / `super.onNewIntent`, and (in `onCreate`)
 * before any read of `getIntent()`. Compared by source position inside the same method; branches,
 * loops and calls to helper methods are not followed (docs/LIMITATIONS.md L41).
 */
internal object CallOrder {
    fun check(context: JavaContext, guardCall: UCallExpression, method: UMethod, guardMethod: String) {
        val guardStart = GuardCallChecks.startOf(guardCall) ?: return
        var earliest: Pair<Int, String>? = null
        fun note(offset: Int?, what: String) {
            if (offset != null && offset < guardStart && (earliest == null || offset < earliest!!.first)) earliest = offset to what
        }
        method.uastBody?.accept(object : AbstractUastVisitor() {
            override fun visitCallExpression(node: UCallExpression): Boolean {
                if (node.receiver is USuperExpression && node.methodName == guardMethod) {
                    note(GuardCallChecks.startOf(node.receiver!!), "`super.$guardMethod`")
                } else if (guardMethod == "onCreate" && node.methodName == "getIntent" && isActivityGetIntent(context, node.resolve())) {
                    note(GuardCallChecks.startOf(node), "a read of `getIntent()`")
                }
                return super.visitCallExpression(node)
            }

            override fun visitSimpleNameReferenceExpression(node: USimpleNameReferenceExpression): Boolean {
                // Kotlin's synthetic property `intent` resolves to Activity.getIntent().
                if (guardMethod == "onCreate" && node.identifier == "intent" && isActivityGetIntent(context, node.resolve())) {
                    note(GuardCallChecks.startOf(node), "a read of `getIntent()`")
                }
                return super.visitSimpleNameReferenceExpression(node)
            }
        })
        val found = earliest ?: return
        context.report(
            ShezGuardDetector.GUARD_CALL_ORDER, guardCall, context.getLocation(guardCall),
            "`ActivityGuard.$guardMethod` runs after ${found.second}; call the guard first, so no base class, " +
                "fragment or library sees the unchecked intent.",
        )
    }

    private fun isActivityGetIntent(context: JavaContext, resolved: PsiElement?): Boolean {
        val method = resolved as? PsiMethod ?: return false
        if (method.name != "getIntent" || method.parameterList.parametersCount != 0) return false
        val owner = method.containingClass ?: return false
        return context.evaluator.extendsClass(owner, ShezGuardDetector.ACTIVITY, false)
    }
}

/**
 * Issue 5 (heuristic, Warning): a guard result stored in a variable that the same method never
 * compares with `null` and never uses with `?.` or `?:`; and a result asserted with `!!`. A result
 * that is not used at all is left to the built-in CheckResult check.
 */
internal object ResultUse {
    fun check(context: JavaContext, guardCall: UCallExpression, method: UMethod, guardMethod: String) {
        val callPsi = guardCall.sourcePsi ?: return
        // The whole expression the call's value flows out of (`guard.onCreate(this)` is a qualified expression).
        var expr: PsiElement = callPsi
        while (true) {
            val p = expr.parent ?: break
            if ((p is KtDotQualifiedExpression && p.selectorExpression == expr) ||
                p is KtParenthesizedExpression || p is PsiParenthesizedExpression
            ) expr = p else break
        }
        val parent = expr.parent
        val variable: String? = when {
            parent is KtBinaryExpression && parent.operationToken == KtTokens.ELVIS && parent.left == expr -> return
            parent is KtSafeQualifiedExpression && parent.receiverExpression == expr -> return
            parent is KtPostfixExpression && parent.operationToken == KtTokens.EXCLEXCL -> {
                context.report(
                    ShezGuardDetector.UNCHECKED_GUARD_RESULT, guardCall, context.getLocation(guardCall),
                    "The result of `ActivityGuard.$guardMethod` is asserted non-null with `!!`; a Block then " +
                        "crashes the activity instead of stopping. Check for `null` and return.",
                )
                return
            }
            parent is KtProperty && parent.initializer == expr -> parent.name
            parent is KtBinaryExpression && parent.operationToken == KtTokens.EQ && parent.right == expr -> parent.left?.text
            else -> (parent.toUElement() as? UVariable)?.takeIf { it.uastInitializer?.sourcePsi == expr }?.name
                ?: (parent.toUElement() as? UBinaryExpression)
                    ?.takeIf { it.operator == UastBinaryOperator.ASSIGN && it.rightOperand.sourcePsi == expr }
                    ?.leftOperand?.sourcePsi?.text
        }
        if (variable == null) return // not stored: ignored (built-in CheckResult) or passed on directly
        if (isNullChecked(method, variable.substringAfterLast('.'))) return
        context.report(
            ShezGuardDetector.UNCHECKED_GUARD_RESULT, guardCall, context.getLocation(guardCall),
            "The result of `ActivityGuard.$guardMethod` is stored in `$variable` but never checked for `null` in " +
                "this method. `null` means Block: return before using the intent.",
        )
    }

    private fun isNullChecked(method: UMethod, name: String): Boolean {
        var checked = false
        method.uastBody?.accept(object : AbstractUastVisitor() {
            override fun visitSimpleNameReferenceExpression(node: USimpleNameReferenceExpression): Boolean {
                if (node.identifier == name && isNullCheckUse(node)) checked = true
                return super.visitSimpleNameReferenceExpression(node)
            }
        })
        return checked
    }

    private fun isNullCheckUse(ref: USimpleNameReferenceExpression): Boolean {
        val binary = ref.uastParent as? UBinaryExpression
        if (binary != null && binary.operator in NULL_COMPARISONS) {
            val other = if (binary.leftOperand == ref) binary.rightOperand else binary.leftOperand
            if (other is ULiteralExpression && other.isNull) return true
        }
        val psi = ref.sourcePsi ?: return false
        var expr: PsiElement = psi
        while (expr.parent is KtParenthesizedExpression) expr = expr.parent
        val parent = expr.parent
        return (parent is KtBinaryExpression && parent.operationToken == KtTokens.ELVIS && parent.left == expr) ||
            (parent is KtSafeQualifiedExpression && parent.receiverExpression == expr)
    }

    private val NULL_COMPARISONS = setOf(
        UastBinaryOperator.EQUALS, UastBinaryOperator.NOT_EQUALS,
        UastBinaryOperator.IDENTITY_EQUALS, UastBinaryOperator.IDENTITY_NOT_EQUALS,
    )
}
