// Public proof uses fixed failure codes. Detailed browser errors belong to Home.
export function publicJourneyFailure(error, stage, subcheck) {
  const failure_stage = ["sign_in", "model_package_admission", "engine_absent_refusal", "installed_runtime_reply", "memory_refusal", "finite_resource_lifecycle", "finite_home_recovery"].includes(stage) ? stage : "journey";
  const failure = error?.message?.includes("ERR_BLOCKED_BY_RESPONSE") ? "frame_blocked" :
    error?.name === "TimeoutError" ? "timeout" :
    error?.name === "AssertionError" ? "assertion_failed" : "journey_failed";
  const checks = {
    installed_runtime_reply: ["request_cap", "request_authority", "terminal_status", "terminal_output", "reply_display", "reply_bounds"],
    finite_resource_lifecycle: ["owner_configure", "contender_launch", "contender_configure", "owner_start", "busy", "stop", "stop_recovery", "idle", "idle_recovery", "crash", "crash_recovery"],
  };
  const failure_check = checks[failure_stage]?.includes(subcheck) ? subcheck : null;
  return { failure_stage, failure, ...(failure_check ? { failure_check } : {}) };
}
