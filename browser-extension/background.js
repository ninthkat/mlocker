const HOST_NAME = "com.mlocker.native";

const runtimeApi = globalThis.browser || globalThis.chrome;

runtimeApi.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !["mlocker_query_credentials", "mlocker_save_login"].includes(message.type)) {
    return false;
  }

  const tabUrl = message.url || (sender.tab && sender.tab.url) || "";
  let origin = message.origin;
  if (!origin && tabUrl) {
    try {
      origin = new URL(tabUrl).origin;
    } catch (_error) {
      origin = "";
    }
  }

  const request = message.type === "mlocker_save_login"
    ? {
        type: "save_login",
        origin,
        url: tabUrl,
        title: message.title || "",
        username: message.username || "",
        password: message.password || ""
      }
    : {
        type: "credential_query",
        origin,
        url: tabUrl
      };

  if (globalThis.browser && browser.runtime && browser.runtime.sendNativeMessage) {
    browser.runtime.sendNativeMessage(HOST_NAME, request).then(
      (response) => sendResponse(response || { type: "credential_suggestions", items: [] }),
      (error) => sendResponse({ type: "error", message: String(error && error.message || error) })
    );
    return true;
  }

  chrome.runtime.sendNativeMessage(HOST_NAME, request, (response) => {
    const lastError = chrome.runtime.lastError;
    if (lastError) {
      sendResponse({ type: "error", message: lastError.message });
      return;
    }
    sendResponse(response || { type: "credential_suggestions", items: [] });
  });

  return true;
});
