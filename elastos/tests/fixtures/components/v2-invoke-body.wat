;; The guest sends a stream to invoke, then writes after unavailable returns.
;; Closing the host reader completes the write with a dropped-reader result.
(component
  (import "elastos:bus/types@2.0.0" (instance $types
    (type $request (record (field "resource" string) (field "operation" string)
      (field "grant" (option string)) (field "params" (list u8))))
    (export "invoke-request" (type (eq $request)))
    (type $status (record (field "status" string) (field "audit" (option string))))
    (export "invoke-status" (type (eq $status)))
    (type $error (variant
      (case "denied" string) (case "not-found" string) (case "invalid" string)
      (case "unavailable" string) (case "timeout" string) (case "conflict" string)
      (case "internal" string)))
    (export "bus-error" (type (eq $error)))
    (type $grant-id string)
    (export "grant-id" (type (eq $grant-id)))
    (type $event (variant (case "stop-requested") (case "user-input" (list u8))
      (case "message" (list u8)) (case "grant-revoked" $grant-id)))
    (export "event" (type (eq $event)))))
  (alias export $types "invoke-request" (type $request))
  (alias export $types "invoke-status" (type $status))
  (alias export $types "bus-error" (type $error))
  (alias export $types "event" (type $event))
  (type $body (stream u8))
  (type $invoke-result (result (tuple $status $body (future (result (error $error)))) (error $error)))
  (type $invoke (func async (param "request" $request) (param "body" (option $body)) (result $invoke-result)))
  (import "elastos:bus/providers@2.0.0" (instance $providers
    (export "invoke-request" (type (eq $request)))
    (export "invoke-status" (type (eq $status)))
    (export "bus-error" (type (eq $error)))
    (export "invoke" (func (type $invoke)))))
  (alias export $providers "invoke" (func $invoke-f))
  (type $reply (result (error $error)))
  (type $run (func async (param "events" (stream $event)) (result $reply)))
  (core module $shim
    (type $invoke (func (param i32 i32) (result i32)))
    (type $new-stream (func (result i64)))
    (type $write (func (param i32 i32 i32) (result i32)))
    (type $done (func (param i32 i32 i32 i32)))
    (type $new-set (func (result i32)))
    (type $join (func (param i32 i32)))
    (table (export "table") 6 funcref)
    (func (export "invoke") (type $invoke)
      local.get 0 local.get 1 i32.const 0 call_indirect (type $invoke))
    (func (export "new-stream") (type $new-stream)
      i32.const 1 call_indirect (type $new-stream))
    (func (export "write") (type $write)
      local.get 0 local.get 1 local.get 2 i32.const 2 call_indirect (type $write))
    (func (export "done") (type $done)
      local.get 0 local.get 1 local.get 2 local.get 3 i32.const 3 call_indirect (type $done))
    (func (export "new-set") (type $new-set)
      i32.const 4 call_indirect (type $new-set))
    (func (export "join") (type $join)
      local.get 0 local.get 1 i32.const 5 call_indirect (type $join)))
  (core instance $shim-i (instantiate $shim))
  (alias core export $shim-i "invoke" (core func $shim-invoke))
  (alias core export $shim-i "new-stream" (core func $shim-new-stream))
  (alias core export $shim-i "write" (core func $shim-write))
  (alias core export $shim-i "done" (core func $shim-done))
  (alias core export $shim-i "new-set" (core func $shim-new-set))
  (alias core export $shim-i "join" (core func $shim-join))
  (core instance $host (export "invoke" (func $shim-invoke))
    (export "new-stream" (func $shim-new-stream)) (export "write" (func $shim-write))
    (export "done" (func $shim-done)) (export "new-set" (func $shim-new-set))
    (export "join" (func $shim-join)))
  (core module $guest
    (import "host" "invoke" (func $invoke (param i32 i32) (result i32)))
    (import "host" "new-stream" (func $new-stream (result i64)))
    (import "host" "write" (func $write (param i32 i32 i32) (result i32)))
    (import "host" "done" (func $done (param i32 i32 i32 i32)))
    (import "host" "new-set" (func $new-set (result i32)))
    (import "host" "join" (func $join (param i32 i32)))
    (memory (export "memory") 1)
    (data (i32.const 128) "elastos://test/body")
    (data (i32.const 160) "read")
    (data (i32.const 512) "\07")
    (global $heap (mut i32) (i32.const 1024))
    (global $writer (mut i32) (i32.const 0))
    (global $set (mut i32) (i32.const 0))
    (func (export "realloc") (param i32 i32 i32 i32) (result i32)
      (local $old i32)
      global.get $heap local.tee $old
      local.get 3 i32.add global.set $heap
      local.get $old)
    (func $finish
      i32.const 0 i32.const 0 i32.const 0 i32.const 0 call $done)
    (func $after-write (param $code i32) (result i32)
      local.get $code i32.const 15 i32.and i32.const 1 i32.ne
      if unreachable end
      call $finish
      i32.const 0)
    (func $after-invoke (result i32)
      (local $code i32)
      ;; result<tuple<...>,bus-error>: Err(Invalid(...)). Empty read params.
      i32.const 256 i32.load i32.const 1 i32.ne if unreachable end
      i32.const 260 i32.load i32.const 2 i32.ne if unreachable end
      global.get $writer i32.const 512 i32.const 1 call $write
      local.tee $code i32.const -1 i32.eq
      if
        global.get $writer global.get $set call $join
        global.get $set i32.const 4 i32.shl i32.const 2 i32.or return
      end
      local.get $code call $after-write)
    (func (export "run") (param $events i32) (result i32)
      (local $pair i64) (local $code i32)
      call $new-set global.set $set
      call $new-stream local.tee $pair
      i64.const 32 i64.shr_u i32.wrap_i64 global.set $writer
      ;; Canonical ABI request and option<stream<u8>>.
      i32.const 64 i32.const 128 i32.store
      i32.const 68 i32.const 19 i32.store
      i32.const 72 i32.const 160 i32.store
      i32.const 76 i32.const 4 i32.store
      i32.const 80 i32.const 0 i32.store
      i32.const 92 i32.const 0 i32.store
      i32.const 96 i32.const 0 i32.store
      i32.const 100 i32.const 1 i32.store
      i32.const 104 local.get $pair i32.wrap_i64 i32.store
      i32.const 64 i32.const 256 call $invoke
      local.tee $code i32.const 15 i32.and i32.const 2 i32.eq
      if call $after-invoke return end
      local.get $code i32.const 4 i32.shr_u global.get $set call $join
      global.get $set i32.const 4 i32.shl i32.const 2 i32.or)
    (func (export "callback") (param $event i32) (param $handle i32) (param $result i32) (result i32)
      local.get $event i32.const 1 i32.eq
      if
        local.get $result i32.const 2 i32.eq
        if call $after-invoke return end
      end
      local.get $event i32.const 3 i32.eq
      if local.get $result call $after-write return end
      global.get $set i32.const 4 i32.shl i32.const 2 i32.or))
  (core instance $guest-i (instantiate $guest (with "host" (instance $host))))
  (alias core export $guest-i "memory" (core memory $memory))
  (alias core export $guest-i "realloc" (core func $realloc))
  (core func $invoke (canon lower (func $invoke-f) (memory $memory) (realloc $realloc) async))
  (core func $new-stream (canon stream.new $body))
  (core func $write (canon stream.write $body (memory $memory) async))
  (core func $done (canon task.return (result $reply) (memory $memory) string-encoding=utf8))
  (core func $new-set (canon waitable-set.new))
  (core func $join (canon waitable.join))
  (core module $fix
    (import "" "0" (func $invoke (param i32 i32) (result i32)))
    (import "" "1" (func $new-stream (result i64)))
    (import "" "2" (func $write (param i32 i32 i32) (result i32)))
    (import "" "3" (func $done (param i32 i32 i32 i32)))
    (import "" "4" (func $new-set (result i32)))
    (import "" "5" (func $join (param i32 i32)))
    (import "" "$imports" (table 6 funcref))
    (elem (i32.const 0) func $invoke $new-stream $write $done $new-set $join))
  (alias core export $shim-i "table" (core table $table))
  (core instance $fix-args (export "0" (func $invoke))
    (export "1" (func $new-stream)) (export "2" (func $write))
    (export "3" (func $done)) (export "4" (func $new-set))
    (export "5" (func $join)) (export "$imports" (table $table)))
  (core instance $fix-i (instantiate $fix (with "" (instance $fix-args))))
  (alias core export $guest-i "run" (core func $guest-run))
  (alias core export $guest-i "callback" (core func $guest-callback))
  (func $run (type $run)
    (canon lift (core func $guest-run) (memory $memory) async (callback $guest-callback)))
  (instance $lifecycle (export "run" (func $run)))
  (export "elastos:bus/lifecycle@2.0.0" (instance $lifecycle)))
