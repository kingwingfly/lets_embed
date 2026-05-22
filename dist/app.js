const $ = (s) => document.querySelector(s);
const postsEl = $("#posts"),
    imagesEl = $("#images"),
    statusEl = $("#status"),
    postsSection = $("#posts-section"),
    imagesSection = $("#images-section"),
    sentinel = $("#sentinel");

const state = {
    mode: "tag",
    queries: [],
    excludes: [],
    limit: 20,
    offset: 0,
    loading: false,
    done: false,
    searched: false,
    fillLock: false,
    abort: null,
};

$("#search-form").addEventListener("submit", (e) => {
    e.preventDefault();
    resetAndSearch();
});

const csv = (s) =>
    s
        .split(",")
        .map((x) => x.trim())
        .filter(Boolean);

function resetAndSearch() {
    if (state.abort) state.abort.abort();
    postsEl.innerHTML = "";
    imagesEl.innerHTML = "";
    postsSection.hidden = true;
    imagesSection.hidden = true;
    statusEl.textContent = "";

    state.mode = $("#mode").value;
    state.queries = csv($("#query").value);
    state.excludes = csv($("#exclude").value);
    state.limit = parseInt($("#limit").value) || 20;
    state.offset = 0;
    state.done = false;
    state.searched = true;

    if (state.queries.length === 0) {
        statusEl.textContent = "Please enter at least one query.";
        return;
    }
    loadUntilFull();
}

async function loadNext() {
    if (state.loading || state.done) return;
    state.loading = true;
    statusEl.textContent = "Loading…";

    const url = state.mode === "tag" ? "/api/search/tag" : "/api/search/clip";
    const body =
        state.mode === "tag"
            ? {
                  tags: state.queries,
                  not_tags: state.excludes,
                  limit: state.limit,
                  offset: state.offset,
              }
            : {
                  queries: state.queries,
                  limit: state.limit,
                  offset: state.offset,
              };

    state.abort = new AbortController();
    let received = 0;

    try {
        const resp = await fetch(url, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                Accept: "text/event-stream",
            },
            body: JSON.stringify(body),
            signal: state.abort.signal,
        });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

        const reader = resp.body.getReader();
        const decoder = new TextDecoder();
        let buf = "";
        while (true) {
            const { value, done } = await reader.read();
            if (done) break;
            buf += decoder.decode(value, { stream: true });
            let idx;
            while ((idx = buf.indexOf("\n\n")) >= 0) {
                const chunk = buf.slice(0, idx);
                buf = buf.slice(idx + 2);
                const ev = parseSse(chunk);
                if (!ev) continue;
                if (ev.event === "post" || ev.event === "image") received++;
                handleEvent(ev);
            }
        }
    } catch (err) {
        if (err.name !== "AbortError") {
            statusEl.textContent = `Error: ${err.message}`;
        }
        state.loading = false;
        return;
    }

    if (received === 0) {
        state.done = true;
        statusEl.textContent =
            state.offset === 0 ? "No results" : "End of results";
    } else {
        state.offset += state.limit;
        statusEl.textContent = "";
    }
    state.loading = false;
}

// 持续加载直到 sentinel 离开视口或服务端 done
async function loadUntilFull() {
    if (state.fillLock) return;
    state.fillLock = true;
    try {
        let rounds = 0;
        while (!state.done && rounds++ < 50) {
            await loadNext();
            // 等一次 layout 让新格子占据空间
            await new Promise((r) => requestAnimationFrame(r));
            const rect = sentinel.getBoundingClientRect();
            const stillVisible = rect.top < window.innerHeight + 300;
            if (!stillVisible) break;
        }
    } finally {
        state.fillLock = false;
    }
}

function parseSse(chunk) {
    let event = "message",
        data = "";
    for (const line of chunk.split("\n")) {
        if (line.startsWith("event:")) event = line.slice(6).trim();
        else if (line.startsWith("data:")) data += line.slice(5).trimStart();
    }
    let parsed = data;
    try {
        parsed = JSON.parse(data);
    } catch {}
    return { event, data: parsed };
}

function handleEvent(ev) {
    switch (ev.event) {
        case "post":
            postsSection.hidden = false;
            renderPost(ev.data);
            break;
        case "image":
            imagesSection.hidden = false;
            renderImage(ev.data, imagesEl);
            break;
        case "done":
            break;
        case "error":
            statusEl.textContent = `Error: ${ev.data}`;
            break;
    }
}

function renderPost(p) {
    const el = document.createElement("article");
    el.className = "post";

    const h = document.createElement("h3");
    h.textContent = p.title;
    el.appendChild(h);

    const grid = document.createElement("div");
    grid.className = "grid";
    el.appendChild(grid);

    for (const img of p.images) renderImage(img, grid);
    postsEl.appendChild(el);
}

function renderImage(img, container) {
    const a = document.createElement("a");
    a.href = img.url;
    a.target = "_blank";
    a.rel = "noopener";

    const im = document.createElement("img");
    im.loading = "lazy";
    im.decoding = "async";
    im.alt = img.name;
    im.src = img.url;
    im.addEventListener("load", () => im.setAttribute("data-loaded", ""));

    a.appendChild(im);
    container.appendChild(a);
}

const io = new IntersectionObserver(
    (entries) => {
        if (entries[0].isIntersecting && state.searched) loadUntilFull();
    },
    { rootMargin: "300px" },
);
io.observe(sentinel);
