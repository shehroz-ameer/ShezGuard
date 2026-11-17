package com.shezguard.benchmark

import androidx.benchmark.junit4.BenchmarkRule
import androidx.benchmark.junit4.measureRepeated
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * androidx.benchmark (Jetpack Microbenchmark) 1.5.0 over the same scenarios (docs/BENCHMARK.md,
 * method B). The library handles warm-up and the measurement loop; its reported times are per
 * iteration averaged over batches, so they are **not** per-call percentiles and are reported in a
 * separate table from method A. The fresh delivered intent is prepared inside
 * `runWithMeasurementDisabled`, as in method A.
 */
@RunWith(AndroidJUnit4::class)
class MicroBenchmark {

    @get:Rule
    val benchmarkRule = BenchmarkRule()

    private fun measure(name: String) {
        val s = Scenarios.all.single { it.name == name }
        val template = s.template()
        benchmarkRule.measureRepeated {
            val intent = runWithMeasurementDisabled { Scenarios.delivered(template) }
            s.run(intent)
        }
    }

    @Test fun simple_link() = measure("simple_link")
    @Test fun many_params() = measure("many_params")
    @Test fun max_length() = measure("max_length")
    @Test fun nested_depth1() = measure("nested_depth1")
    @Test fun nested_depth4() = measure("nested_depth4")
    @Test fun large_bundle() = measure("large_bundle")
    @Test fun early_block_unregistered() = measure("early_block_unregistered")
    @Test fun early_block_scheme() = measure("early_block_scheme")
    @Test fun baseline_app_reads_link() = measure("baseline_app_reads_link")
    @Test fun baseline_app_reads_bundle() = measure("baseline_app_reads_bundle")
    @Test fun baseline_sanitizer_nested1() = measure("baseline_sanitizer_nested1")
}
