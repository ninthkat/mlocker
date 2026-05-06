const mlockerApi = globalThis.browser || globalThis.chrome;
let activePanel = null;
let activeInput = null;

document.addEventListener("focusin", (event) => {
  const input = event.target;
  if (!isLoginInput(input)) {
    return;
  }
  activeInput = input;
  showPanel(input);
});

document.addEventListener("click", (event) => {
  if (!activePanel) {
    return;
  }
  if (activePanel.contains(event.target) || event.target === activeInput) {
    return;
  }
  closePanel();
});

function isLoginInput(element) {
  if (!(element instanceof HTMLInputElement)) {
    return false;
  }
  if (element.disabled || element.readOnly) {
    return false;
  }
  const type = (element.getAttribute("type") || "text").toLowerCase();
  if (type === "password" || type === "email") {
    return true;
  }
  const autocomplete = (element.getAttribute("autocomplete") || "").toLowerCase();
  return autocomplete.includes("username") || autocomplete.includes("email");
}

function showPanel(anchor) {
  closePanel();
  const panel = document.createElement("div");
  panel.className = "mlocker-panel";
  panel.textContent = "mlocker";
  panel.addEventListener("mousedown", (event) => event.preventDefault());
  panel.addEventListener("click", () => loadSuggestions(anchor, panel));
  document.documentElement.appendChild(panel);
  positionPanel(panel, anchor);
  activePanel = panel;
}

function positionPanel(panel, anchor) {
  const rect = anchor.getBoundingClientRect();
  panel.style.left = `${Math.max(8, window.scrollX + rect.left)}px`;
  panel.style.top = `${window.scrollY + rect.bottom + 6}px`;
}

function loadSuggestions(anchor, panel) {
  panel.classList.add("mlocker-panel-open");
  panel.textContent = "Loading...";

  sendRuntimeMessage(
    {
      type: "mlocker_query_credentials",
      origin: window.location.origin,
      url: window.location.href
    },
    (response) => {
      const lastError = mlockerApi.runtime.lastError;
      if (lastError) {
        renderError(panel, lastError.message);
        return;
      }
      if (!response || response.type === "error") {
        renderError(panel, response && response.message ? response.message : "mlocker is locked");
        return;
      }
      renderSuggestions(anchor, panel, response.items || []);
    }
  );
}

function sendRuntimeMessage(message, callback) {
  if (globalThis.browser && browser.runtime && browser.runtime.sendMessage) {
    browser.runtime.sendMessage(message).then(
      (response) => callback(response),
      (error) => callback({ type: "error", message: String(error && error.message || error) })
    );
    return;
  }
  mlockerApi.runtime.sendMessage(message, callback);
}

function renderSuggestions(anchor, panel, items) {
  panel.textContent = "";
  panel.classList.add("mlocker-panel-open");
  const candidate = collectFormCredential(anchor);

  if (items.length === 0) {
    if (candidate) {
      panel.appendChild(saveButton(anchor, panel, candidate));
    } else {
      const empty = document.createElement("div");
      empty.className = "mlocker-empty";
      empty.textContent = "No matching logins";
      panel.appendChild(empty);
    }
    return;
  }

  for (const item of items) {
    const row = document.createElement("button");
    row.type = "button";
    row.className = "mlocker-suggestion";
    row.innerHTML = `<span>${escapeHtml(item.title)}</span><small>${escapeHtml(item.username)}</small>`;
    row.addEventListener("click", () => {
      fillLogin(anchor, item);
      closePanel();
    });
    panel.appendChild(row);
  }

  if (candidate && !items.some((item) => item.username === candidate.username)) {
    panel.appendChild(saveButton(anchor, panel, candidate));
  }
}

function renderError(panel, message) {
  panel.textContent = "";
  panel.classList.add("mlocker-panel-open");
  const error = document.createElement("div");
  error.className = "mlocker-error";
  error.textContent = message;
  panel.appendChild(error);
}

function fillLogin(anchor, item) {
  const root = anchor.form || document;
  const passwordInput = findPasswordInput(root) || (anchor.type === "password" ? anchor : null);
  const usernameInput = findUsernameInput(root, passwordInput, anchor);

  if (usernameInput) {
    setInputValue(usernameInput, item.username || "");
  }
  if (passwordInput) {
    setInputValue(passwordInput, item.password || "");
  }
}

function collectFormCredential(anchor) {
  const root = anchor.form || document;
  const passwordInput = findPasswordInput(root) || (anchor.type === "password" ? anchor : null);
  if (!passwordInput || !passwordInput.value) {
    return null;
  }
  const usernameInput = findUsernameInput(root, passwordInput, anchor);
  const username = usernameInput && usernameInput.value ? usernameInput.value.trim() : "";
  if (!username) {
    return null;
  }
  return {
    username,
    password: passwordInput.value,
    title: document.title || window.location.hostname
  };
}

function saveButton(anchor, panel, candidate) {
  const row = document.createElement("button");
  row.type = "button";
  row.className = "mlocker-suggestion mlocker-save";
  row.innerHTML = `<span>Save to mlocker</span><small>${escapeHtml(candidate.username)}</small>`;
  row.addEventListener("click", () => saveLogin(anchor, panel, candidate));
  return row;
}

function saveLogin(anchor, panel, candidate) {
  panel.textContent = "Saving...";
  sendRuntimeMessage(
    {
      type: "mlocker_save_login",
      origin: window.location.origin,
      url: window.location.href,
      title: candidate.title,
      username: candidate.username,
      password: candidate.password
    },
    (response) => {
      const lastError = mlockerApi.runtime.lastError;
      if (lastError) {
        renderError(panel, lastError.message);
        return;
      }
      if (!response || response.type === "error") {
        renderError(panel, response && response.message ? response.message : "mlocker is locked");
        return;
      }
      panel.textContent = "";
      const saved = document.createElement("div");
      saved.className = "mlocker-empty";
      saved.textContent = "Saved";
      panel.appendChild(saved);
      if (response.item) {
        fillLogin(anchor, response.item);
      }
    }
  );
}

function findPasswordInput(root) {
  return Array.from(root.querySelectorAll("input[type='password']")).find((input) => {
    return !input.disabled && !input.readOnly;
  });
}

function findUsernameInput(root, passwordInput, anchor) {
  const inputs = Array.from(root.querySelectorAll("input")).filter((input) => {
    if (input.disabled || input.readOnly || input === passwordInput) {
      return false;
    }
    const type = (input.getAttribute("type") || "text").toLowerCase();
    if (["hidden", "password", "submit", "button", "checkbox", "radio"].includes(type)) {
      return false;
    }
    return true;
  });

  const preferred = inputs.find((input) => {
    const autocomplete = (input.getAttribute("autocomplete") || "").toLowerCase();
    return autocomplete.includes("username") || autocomplete.includes("email");
  });
  if (preferred) {
    return preferred;
  }

  if (passwordInput) {
    const beforePassword = inputs.filter((input) => {
      return input.compareDocumentPosition(passwordInput) & Node.DOCUMENT_POSITION_FOLLOWING;
    });
    return beforePassword[beforePassword.length - 1] || inputs[0] || null;
  }

  return anchor.type === "password" ? inputs[0] || null : anchor;
}

function setInputValue(input, value) {
  input.focus();
  input.value = value;
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
}

function closePanel() {
  if (activePanel) {
    activePanel.remove();
    activePanel = null;
  }
}

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
