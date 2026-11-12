package com.shezguard.router.demo

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import java.io.File

/**
 * Fake data for the demo (step 11). Canary strings appear only in data an attack must not reach, so
 * a canary in logcat means the attack worked. Attack payloads never contain these strings.
 */
object FakeData {
    const val TAG = "ShezDemo"

    /** In the hidden rows of the products table: reachable only by SQL injection (threat 2). */
    const val CANARY_HIDDEN_ROW = "CANARY-HIDDEN-ROW"

    /** In files/secret.txt: reachable only by path traversal or a file:// load (threats 2, 6). */
    const val CANARY_SECRET = "CANARY-SECRET-7f3a"

    fun seed(context: Context) {
        val files = context.filesDir
        File(files, "public").mkdirs()
        File(files, "public/readme.txt").writeText("Public help text. Nothing secret here.\n")
        File(files, "secret.txt").writeText("$CANARY_SECRET fake API key for the demo only\n")
        Db(context).writableDatabase.use { db ->
            db.execSQL("DELETE FROM products")
            listOf("Blue mug" to 0, "Red pen" to 0, "Green notebook" to 0,
                "$CANARY_HIDDEN_ROW-1 unreleased product" to 1, "$CANARY_HIDDEN_ROW-2 internal price list" to 1,
            ).forEach { (title, hidden) ->
                db.execSQL("INSERT INTO products(title, hidden) VALUES (?, ?)", arrayOf(title, hidden))
            }
        }
    }

    /** A tiny local database. */
    class Db(context: Context) : SQLiteOpenHelper(context, "demo.db", null, 1) {
        override fun onCreate(db: SQLiteDatabase) {
            db.execSQL("CREATE TABLE products(id INTEGER PRIMARY KEY, title TEXT NOT NULL, hidden INTEGER NOT NULL)")
        }

        override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) = Unit
    }

    /** Reads a file relative to the app's files directory, as the demo's file features do. */
    fun readRelative(context: Context, relative: String): String = File(context.filesDir, relative).readText()
}
