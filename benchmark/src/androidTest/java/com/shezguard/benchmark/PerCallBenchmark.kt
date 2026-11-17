package com.shezguard.benchmark

import android.os.Build
import android.os.Debug
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * Per-call timed loop (docs/BENCHMARK.md, method A). For each scenario: 2 000 untimed calls, then
 * 10 000 calls each timed individually with `System.nanoTime()` around the operation only. The
 * fresh delivered intent for each call is prepared outside the timed region. One instrumentation
 * invocation is one "run"; `scripts/bench/run_bench.sh` starts several, each in a new process.
 *
 * Output per scenario: a `[BENCH-PERCALL]` line (median, p95, p99, max, mean; nearest-rank
 * percentiles over all timed calls; ART GC count before and after) and the raw per-call
 * nanoseconds in `<external media dir>/percall/run<k>_<scenario>.txt`.
 */
@RunWith(AndroidJUnit4::class)
class PerCallBenchmark {

    private companion object {
        /** Defaults for results. `run_bench.sh` lowers them only in its script-check mode (not results). */
        const val DEFAULT_WARMUP = 2_000
        const val DEFAULT_SAMPLES = 10_000
    }

    private fun percentile(sorted: LongArray, p: Double): Long =
        sorted[(Math.ceil(p * sorted.size).toInt() - 1).coerceIn(0, sorted.size - 1)]

    private fun gcCount(): String = Debug.getRuntimeStat("art.gc.gc-count") ?: "?"

    @Test
    fun perCall() {
        val args = InstrumentationRegistry.getArguments()
        val run = args.getString("run") ?: "0"
        val warmupCount = args.getString("warmup")?.toInt() ?: DEFAULT_WARMUP
        val sampleCount = args.getString("samples")?.toInt() ?: DEFAULT_SAMPLES
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        @Suppress("DEPRECATION")
        val dir = File(ctx.externalMediaDirs.first(), "percall").apply { mkdirs() }
        for (s in Scenarios.all) {
            val template = s.template()
            var outcome = ""
            repeat(warmupCount) { i ->
                val r = s.run(Scenarios.delivered(template))
                if (i == 0) outcome = Scenarios.outcome(r)
            }
            val gcBefore = gcCount()
            val samples = LongArray(sampleCount)
            var last: Any? = null
            for (i in 0 until sampleCount) {
                val intent = Scenarios.delivered(template)
                val t0 = System.nanoTime()
                last = s.run(intent)
                samples[i] = System.nanoTime() - t0
            }
            val gcAfter = gcCount()
            assertEquals("${s.name}: outcome changed during the run", outcome, Scenarios.outcome(last))
            File(dir, "run${run}_${s.name}.txt").writeText(samples.joinToString("\n", postfix = "\n"))
            val sorted = samples.copyOf().apply { sort() }
            println(
                "[BENCH-PERCALL] run=$run sdk=${Build.VERSION.SDK_INT} scenario=${s.name} outcome=$outcome " +
                    "warmup=$warmupCount n=$sampleCount median_ns=${percentile(sorted, 0.50)} p95_ns=${percentile(sorted, 0.95)} " +
                    "p99_ns=${percentile(sorted, 0.99)} max_ns=${sorted.last()} mean_ns=${samples.average().toLong()} " +
                    "gc_before=$gcBefore gc_after=$gcAfter",
            )
        }
    }
}
