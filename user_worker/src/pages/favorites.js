"use strict";

const PAGE_LIMIT = 40;
const DENSITY_WIDTHS = { compact: 220, medium: 320, large: 440 };
const DENSITY_KEY = "lets-embed:fav-density";

const grid = document.getElementById("fav-grid");
const panel = document.getElementById("fav-panel");
const emptyBox = document.getElementById("likes-empty");
const emptyText = document.getElementById("likes-empty-text");
const emptySwitchBtn = document.getElementById("empty-switch-btn");
const msgEl = document.getElementById("likes-msg");
const loadingEl = document.getElementById("fav-loading");
const moreBtn = document.getElementById("more-btn");
const endEl = document.getElementById("fav-end");

const viewerEl = document.getElementById("fav-viewer");
const viewerStage = document.getElementById("viewer-stage");
const viewerImg = document.getElementById("viewer-img");
const viewerTitle = document.getElementById("viewer-title");
const viewerCounter = document.getElementById("viewer-counter");
const viewerDetails = document.getElementById("viewer-details");
const viewerUnfav = document.getElementById("viewer-unfav");
const viewerClose = document.getElementById("viewer-close");
const viewerPrev = document.getElementById("viewer-prev");
const viewerNext = document.getElementById("viewer-next");

const toastEl = document.getElementById("fav-toast");
const toastText = document.getElementById("fav-toast-text");
const undoBtn = document.getElementById("fav-undo-btn");

const tabButtons = {
  image: document.getElementById("tab-image"),
  post: document.getElementById("tab-post"),
  video: document.getElementById("tab-video"),
};
const countEls = {
  image: document.getElementById("count-image"),
  post: document.getElementById("count-post"),
  video: document.getElementById("count-video"),
};

function makeTabState() {
  return { items: [], cursor: null, loaded: false, loading: false };
}

const tabs = {
  image: makeTabState(),
  post: makeTabState(),
  video: makeTabState(),
};

let activeKind = initialKind();
let density = loadDensity();
let viewerIndex = -1;
let lastFocusedBeforeViewer = null;
let lastRemoved = null;
let toastTimer = null;
let resizeTimer = null;
let autoSwitchedInitial = false;

function initialKind() {
  const hash = (typeof location !== "undefined" && location.hash ? location.hash.slice(1) : "").toLowerCase();
  if (hash === "posts" || hash === "post") return "post";
  if (hash === "videos" || hash === "video") return "video";
  return "image";
}

function loadDensity() {
  try {
    const saved = localStorage.getItem(DENSITY_KEY);
    if (saved && Object.hasOwn(DENSITY_WIDTHS, saved)) return saved;
  } catch (_) {}
  return "medium";
}

function saveDensity(next) {
  density = Object.hasOwn(DENSITY_WIDTHS, next) ? next : "medium";
  try { localStorage.setItem(DENSITY_KEY, density); } catch (_) {}
  for (const btn of document.querySelectorAll(".density-btn")) {
    btn.setAttribute("aria-pressed", String(btn.dataset.size === density));
  }
  renderActiveTab();
}

// Match search/app/src/util.rs::encode_path: preserve `/` separators while
// percent-encoding each path segment.
function encodePath(path) {
  return String(path || "").split("/").map(encodeURIComponent).join("/");
}

function imageUrl(name) {
  return "/images/" + encodePath(name) + ".webp";
}

function detailsHref(imageId) {
  const id = encodeURIComponent(imageId);
  return "/details/" + id + "?mode=similar&q=" + id + "&limit=50";
}

function formatShortDate(epochSecs) {
  if (!Number.isFinite(epochSecs)) return "";
  try {
    return new Date(epochSecs * 1000).toLocaleDateString(undefined, {
      year: "numeric", month: "short", day: "numeric",
    });
  } catch (_) {
    return new Date(epochSecs * 1000).toLocaleDateString();
  }
}

function itemLabel(item) {
  if (item.kind === "post") {
    return (item.preview && item.preview.title) ? item.preview.title : ("Post #" + item.target_id);
  }
  if (item.kind === "image") return "Image #" + item.target_id;
  return "Video #" + item.target_id;
}

function itemDetailsUrl(item) {
  if (item.kind === "image") {
    return detailsHref(item.preview ? item.preview.image_id : item.target_id);
  }
  if (item.kind === "post" && item.preview && item.preview.image_id != null) {
    return detailsHref(item.preview.image_id);
  }
  return null;
}

function showError(text) {
  if (!text) {
    msgEl.hidden = true;
    msgEl.textContent = "";
    return;
  }
  msgEl.hidden = false;
  msgEl.textContent = text;
}

function updateCountBadge(kind) {
  const st = tabs[kind];
  const el = countEls[kind];
  if (!el) return;
  if (!st.loaded) {
    el.hidden = true;
    return;
  }
  el.hidden = false;
  el.textContent = st.cursor != null ? (st.items.length + "+") : String(st.items.length);
}

function syncTabSelection() {
  for (const kind of ["image", "post", "video"]) {
    const btn = tabButtons[kind];
    if (!btn) continue;
    btn.setAttribute("aria-selected", String(kind === activeKind));
  }
  panel.setAttribute("aria-labelledby", "tab-" + activeKind);
}

function getColumnCount() {
  const target = DENSITY_WIDTHS[density] || 320;
  const width = grid.clientWidth || (typeof window !== "undefined" ? window.innerWidth - 28 : 1120);
  if (width <= 540) return density === "large" ? 1 : 2;
  return Math.max(1, Math.min(6, Math.round(width / target)));
}

function aspectRatioFor(item) {
  const p = item.preview;
  if (p && p.width > 0 && p.height > 0) return { w: p.width, h: p.height };
  return { w: 4, h: 3 };
}

function previewableItems(kind) {
  return tabs[kind].items.filter(it => it.preview && it.preview.name);
}

function buildTile(item) {
  const tile = document.createElement("article");
  const isPost = item.kind === "post";
  const hasPreview = !!(item.preview && item.preview.name);
  tile.className = "fav-tile " + (isPost ? "fav-post" : "fav-image") + (hasPreview ? "" : " fav-fallback");

  const frame = document.createElement("div");
  frame.className = "fav-frame";
  tile.appendChild(frame);

  const href = itemDetailsUrl(item);
  const label = itemLabel(item);
  const dateText = formatShortDate(item.created_at);

  const topRight = document.createElement("div");
  topRight.className = "fav-top-right";

  if (isPost && hasPreview) {
    const zoomBtn = document.createElement("button");
    zoomBtn.type = "button";
    zoomBtn.className = "fav-icon-btn";
    zoomBtn.textContent = "⤢";
    zoomBtn.title = "Inspect cover";
    zoomBtn.setAttribute("aria-label", "Inspect cover of " + label);
    zoomBtn.addEventListener("click", function (ev) {
      ev.stopPropagation();
      ev.preventDefault();
      openViewerForItem(item, zoomBtn);
    });
    topRight.appendChild(zoomBtn);
  }

  const unfavBtn = document.createElement("button");
  unfavBtn.type = "button";
  unfavBtn.className = "fav-icon-btn unfav";
  unfavBtn.textContent = isPost ? "★" : "♥";
  unfavBtn.title = "Remove from favorites";
  unfavBtn.setAttribute("aria-label", "Remove " + label + " from favorites");
  unfavBtn.addEventListener("click", function (ev) {
    ev.stopPropagation();
    ev.preventDefault();
    removeLike(item, unfavBtn);
  });
  topRight.appendChild(unfavBtn);
  frame.appendChild(topRight);

  if (hasPreview) {
    const dims = aspectRatioFor(item);
    const img = document.createElement("img");
    img.className = "fav-img";
    img.loading = "lazy";
    img.decoding = "async";
    img.alt = label;
    img.src = imageUrl(item.preview.name);
    img.style.aspectRatio = dims.w + " / " + dims.h;

    if (isPost) {
      const topLeft = document.createElement("div");
      topLeft.className = "fav-top-left";
      const pill = document.createElement("span");
      pill.className = "fav-post-pill";
      const star = document.createElement("span");
      star.className = "star";
      star.textContent = "★";
      const text = item.preview.image_count
        ? ("Post · " + item.preview.image_count + "p")
        : "Post";
      pill.append(star, " " + text);
      topLeft.appendChild(pill);
      frame.appendChild(topLeft);

      const link = document.createElement("a");
      link.className = "fav-media-trigger";
      link.href = href || "#";
      link.setAttribute("aria-label", "Open " + label);
      link.appendChild(img);
      frame.appendChild(link);
    } else {
      const trigger = document.createElement("button");
      trigger.type = "button";
      trigger.className = "fav-media-trigger";
      trigger.setAttribute("aria-label", "View " + label + " full screen");
      trigger.appendChild(img);
      trigger.addEventListener("click", function () {
        openViewerForItem(item, trigger);
      });
      frame.appendChild(trigger);
    }

    const overlay = document.createElement("div");
    overlay.className = "fav-overlay";
    const meta = document.createElement("span");
    meta.className = "fav-overlay-meta";
    meta.textContent = isPost
      ? (label + (dateText ? " · " + dateText : ""))
      : (dateText || label);
    overlay.appendChild(meta);

    if (href) {
      const dLink = document.createElement("a");
      dLink.className = "fav-overlay-link";
      dLink.href = href;
      dLink.textContent = isPost ? "Open post ↗" : "Details ↗";
      dLink.addEventListener("click", function (ev) { ev.stopPropagation(); });
      overlay.appendChild(dLink);
    }
    frame.appendChild(overlay);
  } else {
    const body = document.createElement("div");
    body.className = "fav-fallback-body";
    const badge = document.createElement("span");
    badge.className = "badge " + (item.kind === "video" ? "warn" : "ok");
    badge.textContent = item.kind;
    body.appendChild(badge);
    if (href) {
      const a = document.createElement("a");
      a.className = "fav-fallback-title";
      a.href = href;
      a.textContent = label + " ↗";
      body.appendChild(a);
    } else {
      const t = document.createElement("span");
      t.className = "fav-fallback-title";
      t.textContent = label;
      body.appendChild(t);
    }
    const d = document.createElement("span");
    d.className = "fav-fallback-date";
    d.textContent = dateText;
    body.appendChild(d);
    frame.appendChild(body);
  }

  return tile;
}

function renderActiveTab() {
  const st = tabs[activeKind];
  syncTabSelection();
  updateCountBadge(activeKind);

  grid.textContent = "";
  const items = st.items;
  const colCount = getColumnCount();
  if (items.length > 0) {
    const cols = [];
    const heights = [];
    for (let i = 0; i < colCount; i++) {
      const col = document.createElement("div");
      col.className = "fav-col";
      grid.appendChild(col);
      cols.push(col);
      heights.push(0);
    }
    for (let i = 0; i < items.length; i++) {
      const item = items[i];
      let shortest = 0;
      for (let c = 1; c < heights.length; c++) {
        if (heights[c] < heights[shortest]) shortest = c;
      }
      const dims = aspectRatioFor(item);
      heights[shortest] += (dims.h / dims.w) + (item.kind === "post" ? 0.08 : 0.04);
      cols[shortest].appendChild(buildTile(item));
    }
  }

  const isEmpty = st.loaded && !st.loading && items.length === 0;
  emptyBox.hidden = !isEmpty;
  if (isEmpty) {
    const otherKind = activeKind === "image" ? "post" : "image";
    emptyText.textContent = activeKind === "image"
      ? "No favorite single images yet."
      : activeKind === "post"
        ? "No favorite posts yet."
        : "No favorite videos yet.";
    if (activeKind !== "video") {
      emptySwitchBtn.hidden = false;
      emptySwitchBtn.textContent = otherKind === "post" ? "View favorite posts" : "View favorite images";
      emptySwitchBtn.dataset.targetKind = otherKind;
    } else {
      emptySwitchBtn.hidden = true;
    }
  }

  loadingEl.hidden = !st.loading;
  moreBtn.hidden = st.loading || st.cursor === null || st.cursor === undefined;
  moreBtn.disabled = st.loading;
  endEl.hidden = !st.loaded || st.loading || items.length === 0 || (st.cursor !== null && st.cursor !== undefined);
}

async function fetchPreviews(items) {
  const map = {};
  const pairs = [];
  for (let i = 0; i < items.length; i++) {
    const k = items[i].kind;
    if (k === "post" || k === "image") pairs.push(k + ":" + items[i].target_id);
  }
  if (pairs.length === 0) return map;
  try {
    const r = await fetch("/api/like_previews?items=" + encodeURIComponent(pairs.join(",")));
    if (!r.ok) return map;
    const arr = await r.json();
    for (let j = 0; j < arr.length; j++) {
      map[arr[j].kind + ":" + arr[j].target_id] = arr[j];
    }
  } catch (_) {}
  return map;
}

async function loadTabPage(kind) {
  const st = tabs[kind];
  if (st.loading) return;
  st.loading = true;
  if (kind === activeKind) {
    showError("");
    renderActiveTab();
  }
  try {
    let url = "/user/api/likes?kind=" + encodeURIComponent(kind) + "&limit=" + PAGE_LIMIT;
    if (st.cursor !== null) url += "&cursor=" + encodeURIComponent(st.cursor);
    const r = await fetch(url);
    if (r.status === 401) {
      location = "/user/login?next=/user/favorites";
      return;
    }
    if (!r.ok) {
      let err;
      try { err = (await r.json()).error; } catch (_) {}
      showError(err || "Failed to load favorites (" + r.status + ")");
      return;
    }
    const data = await r.json();
    const previews = await fetchPreviews(data.items || []);
    const existingKeys = new Set(st.items.map(it => it.kind + ":" + it.target_id));
    for (let i = 0; i < (data.items || []).length; i++) {
      const it = data.items[i];
      const key = it.kind + ":" + it.target_id;
      if (existingKeys.has(key)) continue;
      existingKeys.add(key);
      st.items.push({
        kind: it.kind,
        target_id: it.target_id,
        created_at: it.created_at,
        preview: previews[key] || null,
      });
    }
    st.loaded = true;
    st.cursor = data.next_cursor ?? null;
    updateCountBadge(kind);

    // If user landed on default Images tab with zero single images, check if Posts has favorites.
    if (kind === "image" && activeKind === "image" && !autoSwitchedInitial
        && st.items.length === 0 && !(typeof location !== "undefined" && location.hash)) {
      autoSwitchedInitial = true;
      await loadTabPage("post");
      if (tabs.post.items.length > 0 && activeKind === "image") {
        selectTab("post", false);
        return;
      }
    }
  } catch (e) {
    showError(e && e.message ? e.message : String(e));
  } finally {
    st.loading = false;
    updateCountBadge(kind);
    if (kind === activeKind) renderActiveTab();
    if (!viewerEl.hidden) syncViewer();
  }
}

async function probeVideosTab() {
  try {
    const r = await fetch("/user/api/likes?kind=video&limit=1");
    if (!r.ok) return;
    const data = await r.json();
    if (data && Array.isArray(data.items) && data.items.length > 0 && tabButtons.video) {
      tabButtons.video.hidden = false;
    }
  } catch (_) {}
}

function selectTab(kind, updateHash = true) {
  if (!Object.hasOwn(tabs, kind)) return;
  activeKind = kind;
  if (updateHash && typeof history !== "undefined" && history.replaceState) {
    const nextHash = kind === "post" ? "#posts" : kind === "video" ? "#videos" : "#images";
    try { history.replaceState(null, "", nextHash); } catch (_) {}
  }
  closeViewer();
  showError("");
  renderActiveTab();
  if (!tabs[kind].loaded && !tabs[kind].loading) {
    loadTabPage(kind);
  }
}

// ---- Undo toast & removal --------------------------------------------------

function showToast(text) {
  toastText.textContent = text;
  toastEl.hidden = false;
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(function () {
    toastEl.hidden = true;
    lastRemoved = null;
  }, 6000);
}

async function removeLike(item, triggerBtn) {
  if (triggerBtn) triggerBtn.disabled = true;
  try {
    const r = await fetch("/user/api/like", {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ kind: item.kind, target_id: item.target_id }),
    });
    if (r.status === 401) {
      location = "/user/login?next=/user/favorites";
      return;
    }
    if (!r.ok) {
      let err;
      try { err = (await r.json()).error; } catch (_) {}
      showError(err || "Failed to remove favorite (" + r.status + ")");
      if (triggerBtn) triggerBtn.disabled = false;
      return;
    }
    const st = tabs[item.kind];
    const idx = st.items.findIndex(x => x.kind === item.kind && x.target_id === item.target_id);
    if (idx >= 0) {
      st.items.splice(idx, 1);
      lastRemoved = { item, index: idx };
      showToast("Removed " + itemLabel(item));
    }
    updateCountBadge(item.kind);
    if (item.kind === activeKind) {
      renderActiveTab();
      if (!viewerEl.hidden) {
        const list = previewableItems(activeKind);
        if (list.length === 0) {
          closeViewer();
        } else {
          if (viewerIndex >= list.length) viewerIndex = list.length - 1;
          syncViewer();
        }
      }
    }
  } catch (e) {
    showError(e && e.message ? e.message : String(e));
    if (triggerBtn) triggerBtn.disabled = false;
  }
}

async function undoLastRemoval() {
  if (!lastRemoved) return;
  const entry = lastRemoved;
  lastRemoved = null;
  undoBtn.disabled = true;
  try {
    const r = await fetch("/user/api/like", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ kind: entry.item.kind, target_id: entry.item.target_id }),
    });
    if (r.status === 401) {
      location = "/user/login?next=/user/favorites";
      return;
    }
    if (!r.ok) {
      showError("Could not restore favorite (" + r.status + ")");
      return;
    }
    const st = tabs[entry.item.kind];
    const pos = Math.min(entry.index, st.items.length);
    st.items.splice(pos, 0, entry.item);
    updateCountBadge(entry.item.kind);
    if (entry.item.kind === activeKind) {
      renderActiveTab();
      if (!viewerEl.hidden) syncViewer();
    }
    toastEl.hidden = true;
  } catch (e) {
    showError(e && e.message ? e.message : String(e));
  } finally {
    undoBtn.disabled = false;
  }
}

// ---- Full-screen Lightbox Viewer -------------------------------------------

function openViewerForItem(item, triggerEl) {
  const list = previewableItems(activeKind);
  const idx = list.findIndex(x => x.kind === item.kind && x.target_id === item.target_id);
  if (idx < 0) return;
  lastFocusedBeforeViewer = triggerEl || document.activeElement;
  viewerIndex = idx;
  viewerEl.hidden = false;
  if (document.body) document.body.style.overflow = "hidden";
  syncViewer();
  if (viewerClose && viewerClose.focus) viewerClose.focus();
}

function closeViewer() {
  if (viewerEl.hidden) return;
  viewerEl.hidden = true;
  viewerIndex = -1;
  if (document.body) document.body.style.overflow = "";
  if (lastFocusedBeforeViewer && lastFocusedBeforeViewer.focus) {
    try { lastFocusedBeforeViewer.focus(); } catch (_) {}
  }
  lastFocusedBeforeViewer = null;
}

function syncViewer() {
  const list = previewableItems(activeKind);
  if (viewerIndex < 0 || viewerIndex >= list.length) {
    closeViewer();
    return;
  }
  const item = list[viewerIndex];
  const label = itemLabel(item);
  const dateText = formatShortDate(item.created_at);
  viewerImg.src = imageUrl(item.preview.name);
  viewerImg.alt = label;
  viewerTitle.textContent = label + (dateText ? " · " + dateText : "");
  viewerCounter.textContent = (viewerIndex + 1) + " / " + list.length;
  const href = itemDetailsUrl(item);
  if (href) {
    viewerDetails.href = href;
    viewerDetails.textContent = item.kind === "post" ? "Open post ↗" : "Details & similar ↗";
    viewerDetails.hidden = false;
  } else {
    viewerDetails.hidden = true;
  }
  viewerUnfav.disabled = false;
  viewerUnfav.textContent = item.kind === "post" ? "★ Remove" : "♥ Remove";
  viewerPrev.disabled = viewerIndex <= 0;
  viewerNext.disabled = viewerIndex >= list.length - 1;
}

function stepViewer(delta) {
  const list = previewableItems(activeKind);
  const next = viewerIndex + delta;
  if (next >= 0 && next < list.length) {
    viewerIndex = next;
    syncViewer();
  }
}

// ---- Wire up events --------------------------------------------------------

for (const kind of ["image", "post", "video"]) {
  const btn = tabButtons[kind];
  if (btn) btn.addEventListener("click", function () { selectTab(kind, true); });
}

for (const btn of document.querySelectorAll(".density-btn")) {
  btn.setAttribute("aria-pressed", String(btn.dataset.size === density));
  btn.addEventListener("click", function () { saveDensity(btn.dataset.size); });
}

emptySwitchBtn.addEventListener("click", function () {
  if (emptySwitchBtn.dataset.targetKind) selectTab(emptySwitchBtn.dataset.targetKind, true);
});

moreBtn.addEventListener("click", function () { loadTabPage(activeKind); });
undoBtn.addEventListener("click", undoLastRemoval);

viewerClose.addEventListener("click", closeViewer);
viewerPrev.addEventListener("click", function (ev) { ev.stopPropagation(); stepViewer(-1); });
viewerNext.addEventListener("click", function (ev) { ev.stopPropagation(); stepViewer(1); });
viewerUnfav.addEventListener("click", function (ev) {
  ev.stopPropagation();
  const list = previewableItems(activeKind);
  if (viewerIndex >= 0 && viewerIndex < list.length) {
    removeLike(list[viewerIndex], viewerUnfav);
  }
});
viewerStage.addEventListener("click", function (ev) {
  if (ev.target === viewerStage) closeViewer();
});
viewerImg.addEventListener("click", function (ev) { ev.stopPropagation(); });

let touchStartX = null;
viewerStage.addEventListener("touchstart", function (ev) {
  if (ev.touches && ev.touches.length === 1) touchStartX = ev.touches[0].clientX;
});
viewerStage.addEventListener("touchend", function (ev) {
  if (touchStartX === null || !ev.changedTouches || !ev.changedTouches.length) return;
  const dx = ev.changedTouches[0].clientX - touchStartX;
  touchStartX = null;
  if (dx <= -40) stepViewer(1);
  else if (dx >= 40) stepViewer(-1);
});

window.addEventListener("keydown", function (ev) {
  if (viewerEl.hidden || ev.altKey || ev.ctrlKey || ev.metaKey) return;
  if (ev.key === "Escape" || ev.key === " ") {
    ev.preventDefault();
    closeViewer();
  } else if (ev.key === "ArrowLeft" || ev.key === "k") {
    ev.preventDefault();
    stepViewer(-1);
  } else if (ev.key === "ArrowRight" || ev.key === "j") {
    ev.preventDefault();
    stepViewer(1);
  }
});

window.addEventListener("resize", function () {
  if (resizeTimer) clearTimeout(resizeTimer);
  resizeTimer = setTimeout(renderActiveTab, 140);
});

syncTabSelection();
loadTabPage(activeKind);
probeVideosTab();
