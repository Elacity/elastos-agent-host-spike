/* The same three answers for a tool and a hosted model.
   Choosing one does not allow it. */

const ANSWERS = [
  ["allow-once", "Once"],
  ["allow-session", "This session"],
  ["standing", "Until I stop it"],
];

export function bindApproval() {
  const sheet = document.querySelector("#approval-sheet");
  if (!sheet || sheet.dataset.bound === "true") {
    return;
  }
  sheet.dataset.bound = "true";
  const status = sheet.querySelector("[data-status]");
  for (const row of sheet.querySelectorAll("[data-ask]")) {
    for (const [name, label] of ANSWERS) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "el-button approval-choice";
      button.textContent = label;
      button.dataset.answer = name;
      button.addEventListener("click", () => {
        row.dataset.choice = name;
        row.dataset.grant = "absent";
        if (status) {
          const who = row.dataset.ask === "hosted" ? "Hosted model" : "Tool";
          status.dataset.status = name;
          status.dataset.grant = "absent";
          status.textContent = `${who}: ${label}. Not allowed.`;
        }
      });
      row.appendChild(button);
    }
  }
  document.querySelector("#identity-menu-approval")?.addEventListener("click", () => {
    window.setTimeout(() => {
      sheet.hidden = false;
      sheet.removeAttribute("inert");
    }, 0);
  });
  document.querySelector("#approval-close")?.addEventListener("click", () => {
    sheet.hidden = true;
    sheet.setAttribute("inert", "");
  });
}
