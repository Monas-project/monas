package com.github.monas

import kotlin.test.Test

class MonasWasmModuleProtoTest {
    @Test
    fun `should return sum of two integers`() {
        val monasWasmModuleProto = MonasWasmModuleProto.create()
        val result = monasWasmModuleProto.add(1, 2)
        assert(result == 3) { "Expected 3 but got $result" }
    }
}