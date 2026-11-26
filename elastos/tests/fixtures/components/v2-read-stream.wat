;; Guest read of providers.invoke. One 8-byte object, four bytes at a time.
;; The guest records bytes only after the trailer is ok. An over-cap invoke is
;; an error and this guest reads no chunk. A one-chunk read is then dropped;
;; the trailer is an error and those bytes are not recorded.
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
  (type $unit-result (result (error $error)))
  (type $trailer (future $unit-result))
  (type $invoke-result (result (tuple $status $body $trailer) (error $error)))
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
    (type $read (func (param i32 i32 i32) (result i32)))
    (type $fut (func (param i32 i32) (result i32)))
    (type $drop (func (param i32)))
    (type $done (func (param i32 i32 i32 i32)))
    (type $new-set (func (result i32)))
    (type $join (func (param i32 i32)))
    (table (export "table") 7 funcref)
    (func (export "invoke") (type $invoke)
      local.get 0 local.get 1 i32.const 0 call_indirect (type $invoke))
    (func (export "read") (type $read)
      local.get 0 local.get 1 local.get 2 i32.const 1 call_indirect (type $read))
    (func (export "future") (type $fut)
      local.get 0 local.get 1 i32.const 2 call_indirect (type $fut))
    (func (export "drop") (type $drop)
      local.get 0 i32.const 3 call_indirect (type $drop))
    (func (export "done") (type $done)
      local.get 0 local.get 1 local.get 2 local.get 3 i32.const 4 call_indirect (type $done))
    (func (export "new-set") (type $new-set)
      i32.const 5 call_indirect (type $new-set))
    (func (export "join") (type $join)
      local.get 0 local.get 1 i32.const 6 call_indirect (type $join)))
  (core instance $shim-i (instantiate $shim))
  (alias core export $shim-i "invoke" (core func $shim-invoke))
  (alias core export $shim-i "read" (core func $shim-read))
  (alias core export $shim-i "future" (core func $shim-future))
  (alias core export $shim-i "drop" (core func $shim-drop))
  (alias core export $shim-i "done" (core func $shim-done))
  (alias core export $shim-i "new-set" (core func $shim-new-set))
  (alias core export $shim-i "join" (core func $shim-join))
  (core instance $host
    (export "invoke" (func $shim-invoke)) (export "read" (func $shim-read))
    (export "future" (func $shim-future)) (export "drop" (func $shim-drop))
    (export "done" (func $shim-done)) (export "new-set" (func $shim-new-set))
    (export "join" (func $shim-join)))
  (core module $guest
    (import "host" "invoke" (func $invoke (param i32 i32) (result i32)))
    (import "host" "read" (func $read (param i32 i32 i32) (result i32)))
    (import "host" "future" (func $future (param i32 i32) (result i32)))
    (import "host" "drop" (func $drop (param i32)))
    (import "host" "done" (func $done (param i32 i32 i32 i32)))
    (import "host" "new-set" (func $new-set (result i32)))
    (import "host" "join" (func $join (param i32 i32)))
    (memory (export "memory") 1)
    ;; 128 resource, 176 "read", 184 grant, 200 max 8, 220 max 4, 240 needle.
    (data (i32.const 128) "localhost://Users/self/Documents/note.bin")
    (data (i32.const 176) "read")
    (data (i32.const 184) "grant-token")
    (data (i32.const 200) "\7b\22max_bytes\22:8\7d")
    (data (i32.const 220) "\7b\22max_bytes\22:4\7d")
    (data (i32.const 240) "over the cap")
    (data (i32.const 740) "\01\02\03\04\05\06\07\08")
    (data (i32.const 760) "invoke")
    (data (i32.const 768) "status")
    (data (i32.const 776) "audit")
    (data (i32.const 784) "chunk")
    (data (i32.const 792) "end")
    (data (i32.const 800) "trailer")
    (data (i32.const 808) "bytes")
    (data (i32.const 816) "over")
    (data (i32.const 868) "case")
    (data (i32.const 876) "text")
    (data (i32.const 824) "short")
    (data (i32.const 832) "short-byte")
    (data (i32.const 848) "event")
    (data (i32.const 856) "ok")
    (data (i32.const 860) "read-1")
    (global $heap (mut i32) (i32.const 1024))
    (global $set (mut i32) (i32.const 0))
    (global $kind (mut i32) (i32.const 0))
    (global $expect (mut i32) (i32.const 0))
    (global $stream (mut i32) (i32.const 0))
    (global $future (mut i32) (i32.const 0))
    (global $chunks (mut i32) (i32.const 0))
    (func (export "realloc") (param i32 i32 i32 i32) (result i32)
      (local $old i32)
      global.get $heap local.tee $old
      local.get 3 i32.add global.set $heap
      local.get $old)
    (func $fail (param $id i32) (result i32)
      (local $ptr i32) (local $len i32)
      local.get $id i32.const 1 i32.eq if i32.const 760 local.set $ptr i32.const 6 local.set $len end
      local.get $id i32.const 2 i32.eq if i32.const 768 local.set $ptr i32.const 6 local.set $len end
      local.get $id i32.const 3 i32.eq if i32.const 776 local.set $ptr i32.const 5 local.set $len end
      local.get $id i32.const 4 i32.eq if i32.const 784 local.set $ptr i32.const 5 local.set $len end
      local.get $id i32.const 5 i32.eq if i32.const 792 local.set $ptr i32.const 3 local.set $len end
      local.get $id i32.const 6 i32.eq if i32.const 800 local.set $ptr i32.const 7 local.set $len end
      local.get $id i32.const 7 i32.eq if i32.const 808 local.set $ptr i32.const 5 local.set $len end
      local.get $id i32.const 8 i32.eq if i32.const 816 local.set $ptr i32.const 4 local.set $len end
      local.get $id i32.const 12 i32.eq if i32.const 868 local.set $ptr i32.const 4 local.set $len end
      local.get $id i32.const 13 i32.eq if i32.const 876 local.set $ptr i32.const 4 local.set $len end
      local.get $id i32.const 9 i32.eq if i32.const 824 local.set $ptr i32.const 5 local.set $len end
      local.get $id i32.const 10 i32.eq if i32.const 832 local.set $ptr i32.const 10 local.set $len end
      local.get $id i32.const 11 i32.eq if i32.const 848 local.set $ptr i32.const 5 local.set $len end
      i32.const 1 i32.const 2 local.get $ptr local.get $len call $done
      i32.const 0)
    (func $eq (param $ptr i32) (param $len i32) (param $at i32) (param $n i32) (result i32)
      (local $i i32)
      local.get $len local.get $n i32.ne if i32.const 0 return end
      (loop $scan
        local.get $i local.get $n i32.eq if i32.const 1 return end
        local.get $ptr local.get $i i32.add i32.load8_u
        local.get $at local.get $i i32.add i32.load8_u
        i32.ne if i32.const 0 return end
        local.get $i i32.const 1 i32.add local.set $i
        br $scan)
      unreachable)
    (func $has (param $ptr i32) (param $len i32) (param $at i32) (param $n i32) (result i32)
      (local $i i32) (local $last i32)
      local.get $len local.get $n i32.lt_u if i32.const 0 return end
      local.get $len local.get $n i32.sub local.set $last
      (loop $scan
        local.get $ptr local.get $i i32.add local.get $n local.get $at local.get $n call $eq
        if i32.const 1 return end
        local.get $i local.get $last i32.eq if i32.const 0 return end
        local.get $i i32.const 1 i32.add local.set $i
        br $scan)
      unreachable)
    (func $same (param $a i32) (param $b i32) (param $n i32) (result i32)
      (local $i i32)
      (loop $scan
        local.get $i local.get $n i32.eq if i32.const 1 return end
        local.get $a local.get $i i32.add i32.load8_u
        local.get $b local.get $i i32.add i32.load8_u
        i32.ne if i32.const 0 return end
        local.get $i i32.const 1 i32.add local.set $i
        br $scan)
      unreachable)
    (func $park (param $handle i32) (result i32)
      local.get $handle global.get $set call $join
      global.get $set i32.const 4 i32.shl i32.const 2 i32.or)
    (func $prepare (param $params i32) (param $len i32)
      i32.const 64 i32.const 128 i32.store
      i32.const 68 i32.const 41 i32.store
      i32.const 72 i32.const 176 i32.store
      i32.const 76 i32.const 4 i32.store
      i32.const 80 i32.const 1 i32.store
      i32.const 84 i32.const 184 i32.store
      i32.const 88 i32.const 11 i32.store
      i32.const 92 local.get $params i32.store
      i32.const 96 local.get $len i32.store
      i32.const 100 i32.const 0 i32.store
      i32.const 104 i32.const 0 i32.store)
    (func $store-chunk
      (local $dst i32)
      i32.const 600 global.get $chunks i32.const 4 i32.mul i32.add local.set $dst
      local.get $dst i32.const 320 i32.load i32.store
      global.get $chunks i32.const 1 i32.add global.set $chunks)
    (func $begin-full (result i32)
      (local $code i32)
      i32.const 200 i32.const 15 call $prepare
      i32.const 64 i32.const 256 call $invoke local.set $code
      local.get $code i32.const 15 i32.and i32.const 2 i32.eq
      if call $full-done return end
      i32.const 0 global.set $kind
      i32.const 1 global.set $expect
      local.get $code i32.const 4 i32.shr_u call $park)
    (func $full-done (result i32)
      i32.const 256 i32.load8_u i32.const 0 i32.ne if i32.const 1 call $fail return end
      i32.const 260 i32.load i32.const 264 i32.load i32.const 856 i32.const 2 call $eq
      i32.eqz if i32.const 2 call $fail return end
      i32.const 268 i32.load8_u i32.const 1 i32.ne if i32.const 3 call $fail return end
      i32.const 272 i32.load i32.const 276 i32.load i32.const 860 i32.const 6 call $eq
      i32.eqz if i32.const 3 call $fail return end
      i32.const 280 i32.load global.set $stream
      i32.const 284 i32.load global.set $future
      i32.const 0 global.set $chunks
      call $read-full)
    (func $read-full (result i32)
      (local $code i32)
      global.get $stream i32.const 320 i32.const 4 call $read local.set $code
      local.get $code i32.const -1 i32.eq
      if
        i32.const 1 global.set $kind
        i32.const 2 global.set $expect
        global.get $stream call $park
        return
      end
      local.get $code call $on-full-read)
    (func $on-full-read (param $code i32) (result i32)
      (local $tag i32) (local $n i32)
      local.get $code i32.const 15 i32.and local.set $tag
      local.get $code i32.const 4 i32.shr_u local.set $n
      local.get $tag i32.eqz
      if
        global.get $chunks i32.const 2 i32.ge_u if i32.const 4 call $fail return end
        local.get $n i32.const 4 i32.ne if i32.const 4 call $fail return end
        call $store-chunk
        call $read-full
        return
      end
      local.get $tag i32.const 1 i32.eq
      if
        local.get $n i32.const 0 i32.ne if i32.const 5 call $fail return end
        global.get $chunks i32.const 2 i32.ne if i32.const 5 call $fail return end
        call $read-full-trailer
        return
      end
      i32.const 4 call $fail)
    (func $read-full-trailer (result i32)
      (local $code i32)
      global.get $future i32.const 512 call $future local.set $code
      local.get $code i32.const -1 i32.eq
      if
        i32.const 2 global.set $kind
        i32.const 4 global.set $expect
        global.get $future call $park
        return
      end
      local.get $code call $on-full-trailer)
    (func $on-full-trailer (param $code i32) (result i32)
      local.get $code i32.const 15 i32.and i32.const 0 i32.ne if i32.const 6 call $fail return end
      i32.const 512 i32.load8_u i32.const 0 i32.ne if i32.const 6 call $fail return end
      i32.const 400 i32.const 0 i32.store
      i32.const 600 i32.const 740 i32.const 8 call $same i32.eqz if i32.const 7 call $fail return end
      global.get $stream call $drop
      call $begin-over)
    (func $begin-over (result i32)
      (local $code i32)
      i32.const 220 i32.const 15 call $prepare
      i32.const 64 i32.const 256 call $invoke local.set $code
      local.get $code i32.const 15 i32.and i32.const 2 i32.eq
      if call $over-done return end
      i32.const 3 global.set $kind
      i32.const 1 global.set $expect
      local.get $code i32.const 4 i32.shr_u call $park)
    (func $over-done (result i32)
      i32.const 256 i32.load8_u i32.const 1 i32.ne if i32.const 8 call $fail return end
      i32.const 260 i32.load8_u i32.const 2 i32.ne if i32.const 12 call $fail return end
      i32.const 264 i32.load i32.const 268 i32.load i32.const 240 i32.const 12 call $has
      i32.eqz if i32.const 13 call $fail return end
      i32.const 412 i32.const 1 i32.store
      call $begin-short)
    (func $begin-short (result i32)
      (local $code i32)
      i32.const 200 i32.const 15 call $prepare
      i32.const 64 i32.const 256 call $invoke local.set $code
      local.get $code i32.const 15 i32.and i32.const 2 i32.eq
      if call $short-done return end
      i32.const 4 global.set $kind
      i32.const 1 global.set $expect
      local.get $code i32.const 4 i32.shr_u call $park)
    (func $short-done (result i32)
      i32.const 256 i32.load8_u i32.const 0 i32.ne if i32.const 9 call $fail return end
      i32.const 280 i32.load global.set $stream
      i32.const 284 i32.load global.set $future
      call $read-short)
    (func $read-short (result i32)
      (local $code i32)
      global.get $stream i32.const 320 i32.const 4 call $read local.set $code
      local.get $code i32.const -1 i32.eq
      if
        i32.const 5 global.set $kind
        i32.const 2 global.set $expect
        global.get $stream call $park
        return
      end
      local.get $code call $on-short-read)
    (func $on-short-read (param $code i32) (result i32)
      local.get $code i32.const 15 i32.and i32.const 0 i32.ne if i32.const 4 call $fail return end
      local.get $code i32.const 4 i32.shr_u i32.const 4 i32.ne if i32.const 4 call $fail return end
      i32.const 320 i32.const 740 i32.const 4 call $same i32.eqz if i32.const 4 call $fail return end
      global.get $chunks i32.const 2 i32.ne if i32.const 10 call $fail return end
      global.get $stream call $drop
      call $read-short-trailer)
    (func $read-short-trailer (result i32)
      (local $code i32)
      global.get $future i32.const 512 call $future local.set $code
      local.get $code i32.const -1 i32.eq
      if
        i32.const 6 global.set $kind
        i32.const 4 global.set $expect
        global.get $future call $park
        return
      end
      local.get $code call $on-short-trailer)
    (func $on-short-trailer (param $code i32) (result i32)
      local.get $code i32.const 15 i32.and i32.const 0 i32.ne if i32.const 6 call $fail return end
      i32.const 512 i32.load8_u i32.const 1 i32.ne if i32.const 9 call $fail return end
      i32.const 408 i32.const 1 i32.store
      i32.const 600 i32.const 740 i32.const 8 call $same i32.eqz if i32.const 10 call $fail return end
      i32.const 608 i32.load8_u i32.const 0 i32.ne if i32.const 10 call $fail return end
      i32.const 400 i32.load i32.const 0 i32.ne if i32.const 6 call $fail return end
      i32.const 412 i32.load i32.const 1 i32.ne if i32.const 8 call $fail return end
      global.get $chunks i32.const 2 i32.ne if i32.const 5 call $fail return end
      i32.const 0 i32.const 0 i32.const 0 i32.const 0 call $done
      i32.const 0)
    (func (export "run") (param $events i32) (result i32)
      i32.const 400 i32.const 7 i32.store
      i32.const 408 i32.const 7 i32.store
      i32.const 412 i32.const 7 i32.store
      call $new-set global.set $set
      call $begin-full)
    (func (export "callback") (param $event i32) (param $handle i32) (param $result i32) (result i32)
      local.get $event global.get $expect i32.ne if i32.const 11 call $fail return end
      global.get $kind i32.const 0 i32.eq if local.get $result i32.const 2 i32.ne if i32.const 1 call $fail return end call $full-done return end
      global.get $kind i32.const 1 i32.eq if local.get $result call $on-full-read return end
      global.get $kind i32.const 2 i32.eq if local.get $result call $on-full-trailer return end
      global.get $kind i32.const 3 i32.eq if local.get $result i32.const 2 i32.ne if i32.const 8 call $fail return end call $over-done return end
      global.get $kind i32.const 4 i32.eq if local.get $result i32.const 2 i32.ne if i32.const 9 call $fail return end call $short-done return end
      global.get $kind i32.const 5 i32.eq if local.get $result call $on-short-read return end
      global.get $kind i32.const 6 i32.eq if local.get $result call $on-short-trailer return end
      i32.const 11 call $fail))
  (core instance $guest-i (instantiate $guest (with "host" (instance $host))))
  (alias core export $guest-i "memory" (core memory $memory))
  (alias core export $guest-i "realloc" (core func $realloc))
  (core func $invoke (canon lower (func $invoke-f) (memory $memory) (realloc $realloc) string-encoding=utf8 async))
  (core func $read (canon stream.read $body (memory $memory) async))
  (core func $future (canon future.read $trailer (memory $memory) (realloc $realloc) string-encoding=utf8 async))
  (core func $drop (canon stream.drop-readable $body))
  (core func $done (canon task.return (result $reply) (memory $memory) string-encoding=utf8))
  (core func $new-set (canon waitable-set.new))
  (core func $join (canon waitable.join))
  (core module $fix
    (import "" "0" (func $invoke (param i32 i32) (result i32)))
    (import "" "1" (func $read (param i32 i32 i32) (result i32)))
    (import "" "2" (func $future (param i32 i32) (result i32)))
    (import "" "3" (func $drop (param i32)))
    (import "" "4" (func $done (param i32 i32 i32 i32)))
    (import "" "5" (func $new-set (result i32)))
    (import "" "6" (func $join (param i32 i32)))
    (import "" "$imports" (table 7 funcref))
    (elem (i32.const 0) func $invoke $read $future $drop $done $new-set $join))
  (alias core export $shim-i "table" (core table $table))
  (core instance $fix-args
    (export "0" (func $invoke)) (export "1" (func $read))
    (export "2" (func $future)) (export "3" (func $drop))
    (export "4" (func $done)) (export "5" (func $new-set))
    (export "6" (func $join)) (export "$imports" (table $table)))
  (core instance $fix-i (instantiate $fix (with "" (instance $fix-args))))
  (alias core export $guest-i "run" (core func $guest-run))
  (alias core export $guest-i "callback" (core func $guest-callback))
  (func $run (type $run)
    (canon lift (core func $guest-run) (memory $memory) async (callback $guest-callback)))
  (instance $lifecycle (export "run" (func $run)))
  (export "elastos:bus/lifecycle@2.0.0" (instance $lifecycle)))
