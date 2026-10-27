import { cut } from "./docs-render.js";

export const TOKEN_HEADER = "x-elastos-home-token";

/** The launch token from the frame's fragment, or "". */
export function launchToken(hash) {
  return new URLSearchParams(String(hash || "").replace(/^#/, "")).get("home_token") || "";
}

/** The only request this page makes. */
export function pageClient(fetchFn, route, token, fallbackLabel, maxChars) {
  return {
    async get() {
      const response = await fetchFn(route, {
        method: "GET",
        headers: { [TOKEN_HEADER]: token },
        credentials: "omit",
        cache: "no-store",
        redirect: "error",
      });
      if (!response.ok) {
        let trimmed = "";
        try {
          const body = await response.json();
          trimmed = body && typeof body.error === "string" ? body.error.trim() : "";
        } catch {
          trimmed = "";
        }
        const error = new Error(cut(trimmed || null, maxChars, `${fallbackLabel} (${response.status}).`));
        error.status = response.status;
        throw error;
      }
      return response.json();
    },
  };
}
