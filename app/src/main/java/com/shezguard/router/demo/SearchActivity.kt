package com.shezguard.router.demo

import com.shezguard.core.GuardedEntryPoint
import com.shezguard.router.guard.Incoming

/** Threat 2 (injection): https://shezguard.example/search?q=... searches visible products. */
@GuardedEntryPoint("search")
class SearchActivity : DemoActivity() {
    override fun handle(incoming: Incoming) {
        val q = incoming.param("q") ?: ""
        // VULNERABLE (threat 2): the parameter is concatenated into SQL. q = x' OR hidden=1 --
        // returns the hidden rows (CANARY-HIDDEN-ROW-*).
        val sql = "SELECT title FROM products WHERE hidden = 0 AND title LIKE '%$q%'"
        val titles = FakeData.Db(this).readableDatabase.use { db ->
            db.rawQuery(sql, null).use { c -> buildList { while (c.moveToNext()) add(c.getString(0)) } }
        }
        show("results=$titles")
    }
}
