/* VoltStore — frontend behaviour: cart actions, auth forms, checkout,
   and the VeriGate admin control plane. Vanilla JS, no dependencies. */

(function () {
  "use strict";

  //--------------------------------------------------------------------------
  // Toast
  //--------------------------------------------------------------------------
  var toastTimer = null;
  function toast(msg, isError) {
    var el = document.getElementById("toast");
    if (!el) {
      el = document.createElement("div");
      el.id = "toast";
      el.className = "toast";
      document.body.appendChild(el);
    }
    el.textContent = msg;
    el.classList.toggle("err", !!isError);
    el.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { el.classList.remove("show"); }, 2600);
  }

  //--------------------------------------------------------------------------
  // Fetch helper
  //--------------------------------------------------------------------------
  function postJSON(url, data) {
    return fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data || {}),
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (body) {
        if (!r.ok) {
          var err = new Error((body && body.error) || ("HTTP " + r.status));
          err.status = r.status;
          throw err;
        }
        return body;
      });
    });
  }

  function getJSON(url) {
    return fetch(url).then(function (r) {
      return r.json().catch(function () { return {}; });
    });
  }

  //--------------------------------------------------------------------------
  // Cart badge sync
  //--------------------------------------------------------------------------
  function setCartBadge(count) {
    var b = document.querySelector("[data-cart-count]");
    if (!b) return;
    b.textContent = count;
    b.classList.toggle("hidden", count === 0);
  }

  // Add to cart buttons: data-product-id (and optional data-qty input)
  function bindAddToCart(scope) {
    var root = scope || document;
    var buttons = root.querySelectorAll("[data-add-to-cart]");
    Array.prototype.forEach.call(buttons, function (btn) {
      btn.addEventListener("click", function () {
        var id = parseInt(btn.getAttribute("data-add-to-cart"), 10);
        var qtyEl = root.querySelector("[data-qty]");
        var qty = qtyEl ? parseInt(qtyEl.value || "1", 10) : 1;
        if (!id || qty < 1) return;
        btn.disabled = true;
        postJSON("/api/cart/items", { product_id: id, quantity: qty })
          .then(function (res) {
            setCartBadge(res.count);
            toast("Added to cart");
          })
          .catch(function (e) { toast(e.message, true); })
          .finally(function () { btn.disabled = false; });
      });
    });
  }

  // Remove cart line: data-remove-line
  function bindCartRemove() {
    var buttons = document.querySelectorAll("[data-remove-line]");
    Array.prototype.forEach.call(buttons, function (btn) {
      btn.addEventListener("click", function () {
        var id = parseInt(btn.getAttribute("data-remove-line"), 10);
        fetch("/api/cart/items/" + id, { method: "DELETE" })
          .then(function (r) { return r.json(); })
          .then(function (res) {
            setCartBadge(res.count);
            toast("Removed from cart");
            setTimeout(function () { location.reload(); }, 350);
          })
          .catch(function (e) { toast(e.message, true); });
      });
    });
  }

  //--------------------------------------------------------------------------
  // Auth forms
  //--------------------------------------------------------------------------
  function bindAuthForms() {
    var login = document.getElementById("login-form");
    if (login) {
      login.addEventListener("submit", function (ev) {
        ev.preventDefault();
        postJSON("/api/auth/login", {
          email: login.email.value,
          password: login.password.value,
        }).then(function () {
          toast("Welcome back!");
          setTimeout(function () { location.href = "/account"; }, 350);
        }).catch(function (e) {
          toast(e.message, true);
        });
      });
    }

    var reg = document.getElementById("register-form");
    if (reg) {
      reg.addEventListener("submit", function (ev) {
        ev.preventDefault();
        if (reg.password.value !== reg.password2.value) {
          toast("Passwords do not match", true);
          return;
        }
        postJSON("/api/auth/register", {
          name: reg.name.value,
          email: reg.email.value,
          password: reg.password.value,
        }).then(function () {
          toast("Account created!");
          setTimeout(function () { location.href = "/account"; }, 350);
        }).catch(function (e) { toast(e.message, true); });
      });
    }

    var logout = document.getElementById("logout-btn");
    if (logout) {
      logout.addEventListener("click", function () {
        postJSON("/api/auth/logout", {}).then(function () {
          toast("Signed out");
          setTimeout(function () { location.href = "/"; }, 300);
        });
      });
    }
  }

  //--------------------------------------------------------------------------
  // Checkout
  //--------------------------------------------------------------------------
  function bindCheckout() {
    var form = document.getElementById("checkout-form");
    if (!form) return;
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      var btn = form.querySelector("button[type=submit]");
      btn.disabled = true;
      postJSON("/api/checkout", {
        full_name: form.full_name.value,
        address: form.address.value,
        card_last4: form.card_last4.value,
      }).then(function (res) {
        toast("Order " + res.order_id + " placed!");
        setTimeout(function () { location.href = "/account"; }, 500);
      }).catch(function (e) {
        btn.disabled = false;
        if (e.status === 401) {
          toast("Please sign in to check out", true);
          setTimeout(function () { location.href = "/login"; }, 500);
        } else {
          toast(e.message, true);
        }
      });
    });
  }

  //--------------------------------------------------------------------------
  // VeriGate admin control plane
  //--------------------------------------------------------------------------
  function bindAdmin() {
    var page = document.querySelector("[data-page=admin]");
    if (!page) return;

    var toggle = document.getElementById("protect-toggle");
    var statusDot = document.getElementById("gate-dot");
    var statusText = document.getElementById("gate-text");
    var resetBtn = document.getElementById("reset-gate");

    function render(stats) {
      statusDot.className = "dot " + (stats.enabled ? "on" : "off");
      if (stats.enabled) {
        statusText.textContent = "Protection ACTIVE";
      } else {
        statusText.textContent = "Protection DISABLED — site is wide open";
      }
      setKPI("kpi-requests", stats.requests);
      setKPI("kpi-passed", stats.passed);
      setKPI("kpi-limited", stats.rate_limited);
      setKPI("kpi-challenges", stats.challenges_served);
      setKPI("kpi-solved", stats.challenges_solved);
      setKPI("kpi-blocked", stats.requests_blocked);
      setKPI("kpi-blockedips", stats.blocked_ips);
      if (toggle && document.activeElement !== toggle) {
        toggle.checked = stats.enabled;
      }
    }

    function setKPI(id, value) {
      var el = document.getElementById(id);
      if (el) el.textContent = String(value).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
    }

    if (toggle) {
      toggle.addEventListener("change", function () {
        var on = toggle.checked;
        postJSON("/admin/protect", { enabled: on }).then(function (res) {
          toast("VeriGate " + (res.enabled ? "ENABLED" : "DISABLED"));
          return getJSON("/admin/stats").then(render);
        }).catch(function (e) { toast(e.message, true); });
      });
    }

    if (resetBtn) {
      resetBtn.addEventListener("click", function () {
        postJSON("/admin/reset", {}).then(function () {
          toast("Counters + blocks reset");
          return getJSON("/admin/stats").then(render);
        }).catch(function (e) { toast(e.message, true); });
      });
    }

    // Live refresh every 2s.
    getJSON("/admin/stats").then(render);
    setInterval(function () { getJSON("/admin/stats").then(render); }, 2000);
  }

  //--------------------------------------------------------------------------
  // Init
  //--------------------------------------------------------------------------
  document.addEventListener("DOMContentLoaded", function () {
    bindAddToCart(document);
    bindCartRemove();
    bindAuthForms();
    bindCheckout();
    bindAdmin();
  });
})();