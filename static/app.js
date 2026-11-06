const API_TIMEOUT_MS = 12000;
const PASSWORD_MIN_LENGTH = 10;
const PASSWORD_MAX_LENGTH = 128;
const EMAIL_PATTERN = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const PHONE_PATTERN = /^\+?[1-9]\d{6,14}$/;
const STRENGTH_LABELS = ["Password strength", "Too weak", "Weak", "Fair", "Good", "Strong"];

let csrfToken = "";
let csrfRequest = null;

const loginForm = document.getElementById("login-form");
const registerForm = document.getElementById("register-form");
const accountView = document.getElementById("account-view");

function showForm(formName) {
    const showRegister = formName === "register";
    loginForm.hidden = showRegister;
    registerForm.hidden = !showRegister;
    accountView.hidden = true;
    const box = showRegister ? registerForm : loginForm;
    const firstField = box.querySelector("input");
    if (firstField) {
        firstField.focus({ preventScroll: true });
    }
}

function showAccount(account) {
    loginForm.hidden = true;
    registerForm.hidden = true;
    accountView.hidden = false;
    document.getElementById("account-details").textContent =
        `${account.name} · ${account.contact}`;
    const avatar = document.getElementById("account-avatar");
    avatar.textContent = (account.name || "?").trim().charAt(0).toUpperCase();
    document.querySelectorAll('input[name="password"]').forEach((input) => {
        input.value = "";
    });
    history.replaceState(null, "", `${location.pathname}${location.search}`);
}

function messageFor(formName) {
    return document.getElementById(`${formName}-message`);
}

function setMessage(formName, text, tone = "info") {
    const message = messageFor(formName);
    if (!message) {
        return;
    }
    message.textContent = text;
    message.dataset.tone = tone;
}

function activeMethod(form) {
    return form.querySelector(".method-button.active").dataset.identifierMethod;
}

function updateIdentifier(toggle, button) {
    const identifier = toggle.parentElement.querySelector("[data-identifier]");
    const usePhone = button.dataset.identifierMethod === "phone";
    identifier.type = usePhone ? "tel" : "email";
    identifier.placeholder = usePhone ? "Phone number" : "Email address";
    identifier.setAttribute("aria-label", usePhone ? "Phone number" : "Email address");
    identifier.autocomplete = usePhone ? "tel" : "email";
    identifier.inputMode = usePhone ? "tel" : "email";
    identifier.maxLength = usePhone ? 20 : 254;
    setFieldError(identifier, "");

    toggle.querySelectorAll("[data-identifier-method]").forEach((methodButton) => {
        const isActive = methodButton === button;
        methodButton.classList.toggle("active", isActive);
        methodButton.setAttribute("aria-pressed", String(isActive));
    });
}

function setFieldError(input, message) {
    const describedBy = input.getAttribute("aria-describedby") || "";
    const errorId = describedBy.split(/\s+/).find((id) => id.endsWith("-error"));
    const node = errorId ? document.getElementById(errorId) : null;
    input.setAttribute("aria-invalid", message ? "true" : "false");
    input.classList.toggle("is-invalid", Boolean(message));
    if (node) {
        node.textContent = message || "";
        node.hidden = !message;
    }
}

function validateName(input) {
    const value = input.value.trim();
    if (value.length < 2) {
        return "Enter your name (2 to 80 characters).";
    }
    if (value.length > 80) {
        return "Your name must be 80 characters or fewer.";
    }
    return "";
}

function validateIdentifier(input, contactType) {
    const value = input.value.trim();
    if (!value) {
        return contactType === "phone" ? "Enter your phone number." : "Enter your email address.";
    }
    if (contactType === "phone") {
        const digits = value.replace(/[\s().-]/g, "");
        if (!PHONE_PATTERN.test(digits)) {
            return "Enter a phone number with 7 to 15 digits.";
        }
        return "";
    }
    if (value.length > 254 || !EMAIL_PATTERN.test(value)) {
        return "Enter a valid email address.";
    }
    return "";
}

function validatePassword(input, isRegistration) {
    const value = input.value;
    if (!value) {
        return "Enter your password.";
    }
    if (isRegistration && value.length < PASSWORD_MIN_LENGTH) {
        return `Use a password between ${PASSWORD_MIN_LENGTH} and ${PASSWORD_MAX_LENGTH} characters.`;
    }
    if (value.length > PASSWORD_MAX_LENGTH) {
        return `Use a password between ${PASSWORD_MIN_LENGTH} and ${PASSWORD_MAX_LENGTH} characters.`;
    }
    return "";
}

function validateForm(form) {
    const formName = form.dataset.authForm;
    const contactType = activeMethod(form);
    const fields = [form.querySelector("[data-identifier]"), form.querySelector('input[name="password"]')];
    if (formName === "register") {
        fields.unshift(form.querySelector('input[name="name"]'));
    }

    let firstInvalid = null;
    fields.forEach((input) => {
        let message = "";
        if (input.name === "name") {
            message = validateName(input);
        } else if (input.name === "identifier") {
            message = validateIdentifier(input, contactType);
        } else {
            message = validatePassword(input, formName === "register");
        }
        setFieldError(input, message);
        if (message && !firstInvalid) {
            firstInvalid = input;
        }
    });

    if (firstInvalid) {
        setMessage(formName, "Please fix the highlighted field before continuing.", "error");
        firstInvalid.focus({ preventScroll: false });
    }
    return !firstInvalid;
}

function passwordStrength(value) {
    const checks = {
        length: value.length >= PASSWORD_MIN_LENGTH,
        case: /[a-z]/.test(value) && /[A-Z]/.test(value),
        number: /\d/.test(value),
        symbol: /[^A-Za-z0-9]/.test(value),
        long: value.length >= 14,
    };
    if (!checks.length) {
        return { checks, score: 0 };
    }
    let score = 1;
    if (checks.case) score += 1;
    if (checks.number) score += 1;
    if (checks.symbol) score += 1;
    if (checks.long && score > 1) score = Math.min(score + 1, 5);
    return { checks, score: Math.min(score, 5) };
}

function updateStrength(value) {
    const container = document.getElementById("register-strength");
    if (!container) {
        return;
    }
    const { checks, score } = passwordStrength(value);
    const bar = container.querySelector("[data-strength-bar]");
    const label = container.querySelector("[data-strength-label]");
    container.hidden = value.length === 0;
    container.dataset.score = String(score);
    bar.style.width = `${score * 20}%`;
    label.textContent = value.length === 0 ? STRENGTH_LABELS[0] : STRENGTH_LABELS[score];
    container.querySelectorAll("[data-rule]").forEach((rule) => {
        rule.classList.toggle("met", Boolean(checks[rule.dataset.rule]));
    });
}

async function readJson(response) {
    const text = await response.text();
    if (!text) {
        return {};
    }
    try {
        return JSON.parse(text);
    } catch (_error) {
        throw new Error("The server sent an unexpected response. Refresh the page and try again.");
    }
}

async function fetchJson(path, options = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), API_TIMEOUT_MS);
    const headers = new Headers(options.headers);
    headers.set("Accept", "application/json");
    if (options.body) {
        headers.set("Content-Type", "application/json");
        headers.set("X-CSRF-Token", csrfToken);
    }

    try {
        const response = await fetch(path, {
            ...options,
            headers,
            credentials: "same-origin",
            cache: "no-store",
            signal: controller.signal,
        });
        const result = await readJson(response);
        if (!response.ok) {
            const error = new Error(result.error || "Something went wrong. Please try again.");
            error.status = response.status;
            error.code = result.code;
            throw error;
        }
        return result;
    } catch (error) {
        if (error.name === "AbortError") {
            throw new Error("The request timed out. Check your connection and try again.");
        }
        if (error instanceof TypeError) {
            throw new Error("Cannot reach the account service. Start the Python server and refresh.");
        }
        throw error;
    } finally {
        clearTimeout(timer);
    }
}

async function requestCsrfToken() {
    if (csrfToken) {
        return csrfToken;
    }
    if (!csrfRequest) {
        csrfRequest = fetchJson("/api/csrf")
            .then((result) => {
                csrfToken = result.csrfToken;
                return csrfToken;
            })
            .finally(() => {
                csrfRequest = null;
            });
    }
    return csrfRequest;
}

async function apiRequest(path, options = {}, { retryOnExpiredSession = true } = {}) {
    await requestCsrfToken();
    try {
        return await fetchJson(path, options);
    } catch (error) {
        // A long-idle tab can hold a stale token; fetch a fresh one and retry once.
        if (retryOnExpiredSession && error.status === 400 && error.code === "csrf_expired") {
            csrfToken = "";
            await requestCsrfToken();
            return fetchJson(path, options);
        }
        throw error;
    }
}

document.querySelectorAll(".login-method-toggle").forEach((toggle) => {
    toggle.querySelectorAll("[data-identifier-method]").forEach((button) => {
        button.addEventListener("click", () => updateIdentifier(toggle, button));
    });
});

document.querySelectorAll("[data-show-form]").forEach((link) => {
    link.addEventListener("click", (event) => {
        event.preventDefault();
        const formName = link.dataset.showForm;
        showForm(formName);
        history.pushState(null, "", `#${formName}`);
    });
});

window.addEventListener("hashchange", () => {
    showForm(location.hash === "#register" ? "register" : "login");
});

document.querySelectorAll("[data-provider]").forEach((button) => {
    button.addEventListener("click", () => {
        const box = button.closest(".form-box");
        const message = box.querySelector(".auth-message");
        message.textContent = `${button.dataset.provider} sign-in needs OAuth configuration before it can be used.`;
    });
});

document.querySelectorAll("[data-password-toggle]").forEach((button) => {
    button.addEventListener("click", () => {
        const input = document.getElementById(button.getAttribute("aria-controls"));
        if (!input) {
            return;
        }
        const reveal = input.type === "password";
        input.type = reveal ? "text" : "password";
        button.textContent = reveal ? "Hide" : "Show";
        button.setAttribute("aria-pressed", String(reveal));
        button.setAttribute("aria-label", reveal ? "Hide password" : "Show password");
        if (typeof input.setSelectionRange === "function") {
            const end = input.value.length;
            input.setSelectionRange(end, end);
        }
    });
});

document.querySelectorAll('input[type="password"]').forEach((input) => {
    const hint = input.closest(".form-box").querySelector(".caps-lock-hint");
    if (!hint) {
        return;
    }
    const refreshHint = (event) => {
        const active = typeof event.getModifierState === "function" && event.getModifierState("CapsLock");
        hint.hidden = !active;
    };
    input.addEventListener("keydown", refreshHint);
    input.addEventListener("keyup", refreshHint);
    input.addEventListener("blur", () => {
        hint.hidden = true;
    });
});

const strengthInput = document.getElementById("register-password");
if (strengthInput) {
    strengthInput.addEventListener("input", () => updateStrength(strengthInput.value));
    strengthInput.addEventListener("focus", () => updateStrength(strengthInput.value));
    strengthInput.addEventListener("blur", () => {
        if (!strengthInput.value) {
            document.getElementById("register-strength").hidden = true;
        }
    });
}

document.querySelectorAll("[data-auth-form]").forEach((form) => {
    form.noValidate = true;
    form.querySelectorAll("input").forEach((input) => {
        input.addEventListener("input", () => {
            if (input.getAttribute("aria-invalid") === "true") {
                setFieldError(input, "");
            }
            const formName = form.dataset.authForm;
            if (messageFor(formName).dataset.tone === "error") {
                setMessage(formName, "");
            }
        });
    });

    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const formName = form.dataset.authForm;
        const submitButton = form.querySelector('button[type="submit"]');

        if (!validateForm(form)) {
            return;
        }

        const formData = new FormData(form);
        const data = {
            contactType: activeMethod(form),
            identifier: String(formData.get("identifier") || "").trim(),
            password: formData.get("password"),
        };
        if (formName === "register") {
            data.name = String(formData.get("name") || "").trim();
        }

        if (!navigator.onLine) {
            setMessage(formName, "You appear to be offline. Reconnect and try again.", "error");
            return;
        }

        submitButton.disabled = true;
        form.setAttribute("aria-busy", "true");
        setMessage(formName, formName === "register" ? "Creating your account..." : "Signing in...");
        try {
            const result = await apiRequest(`/api/${formName}`, {
                method: "POST",
                body: JSON.stringify(data),
            });
            csrfToken = result.csrfToken || "";
            showAccount(result.account);
        } catch (error) {
            setMessage(formName, error.message, "error");
        } finally {
            submitButton.disabled = false;
            form.removeAttribute("aria-busy");
        }
    });
});

document.getElementById("logout-button").addEventListener("click", async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
        await apiRequest("/api/logout", { method: "POST", body: "{}" });
        csrfToken = "";
        await requestCsrfToken();
        showForm("login");
        history.replaceState(null, "", `${location.pathname}${location.search}#login`);
        setMessage("login", "You have been signed out.", "success");
    } catch (error) {
        setMessage("login", error.message, "error");
        accountView.hidden = false;
    } finally {
        button.disabled = false;
    }
});

async function initialize() {
    showForm(location.hash === "#register" ? "register" : "login");
    try {
        await requestCsrfToken();
        const current = await apiRequest("/api/me", {}, { retryOnExpiredSession: false });
        if (current.authenticated) {
            showAccount(current.account);
        }
    } catch (_error) {
        setMessage(
            "login",
            "The account service is unavailable. Start the Python server and refresh.",
            "error",
        );
    }
}

initialize();
