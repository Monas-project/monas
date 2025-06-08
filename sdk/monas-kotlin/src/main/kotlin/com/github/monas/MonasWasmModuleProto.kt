package com.github.monas

import io.github.charlietap.chasm.embedding.instance
import io.github.charlietap.chasm.embedding.invoke
import io.github.charlietap.chasm.embedding.module
import io.github.charlietap.chasm.embedding.shapes.Instance
import io.github.charlietap.chasm.embedding.shapes.Store
import io.github.charlietap.chasm.embedding.shapes.expect
import io.github.charlietap.chasm.embedding.store
import io.github.charlietap.chasm.runtime.value.NumberValue


class MonasWasmModuleProto private constructor(
    val instance: Instance,
    val store: Store
) {
    companion object {
        fun create() : MonasWasmModuleProto {
            val wasm = object {}.javaClass.getResource("/wasm/wasm_module_proto.wasm")
                ?.readBytes()
                ?: throw IllegalStateException("WASM module not found in resources")
            val module = module(wasm).expect("Failed to load WASM module")
            val store = store()
            val instance = instance(store, module, listOf()).expect("Failed to instantiate WASM module")
            return MonasWasmModuleProto(instance, store)
        }
    }

    fun add(a: Int, b: Int): Int {
        val a = NumberValue.I32(a)
        val b = NumberValue.I32(b)
        val result = invoke(store, instance, "add", listOf(a, b))
            .expect("Failed to invoke 'add' function")
        return (result[0] as NumberValue.I32).value
    }
}