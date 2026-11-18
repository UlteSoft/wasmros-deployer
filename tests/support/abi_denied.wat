;; Assert the result of an explicitly exposed, denied call inside a real VM.
;; An absent import fails at link time. A grant returns ABI major 2.
(module
  (import "uwvm_ros_v2" "abi" (func $abi (result i32)))
  (func (export "_start")
    call $abi
    i32.const 13
    i32.ne
    if
      unreachable
    end))
