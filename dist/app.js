const $ = (s) => document.querySelector(s);
const postsEl = $("#posts"),
    imagesEl = $("#images"),
    statusEl = $("#status");
const postsSection = $("#posts-section"),
    imagesSection = $("#images-section");

const state = {
    mode: "tag",
    queries: [],
    excludes: [],
    limit: 20,
    offset: 0,
    loading: false,
    done: false,
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
    state.mode = $("#mode").value;
    state.queries = csv($("#query").value);
    state.excludes = csv($("#exclude").value);
    state.limit = parseInt($("#limit").value) || 20;
    state.offset = 0;
    state.done = false;
    loadNext();
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
                const e = parseSse(chunk);
                if (!e) continue;
                if (e.event === "post" || e.event === "image") received++;
                handleEvent(e);
            }
        }
    } catch (err) {
        if (err.name !== "AbortError")
            statusEl.textContent = `Error: ${err.message}`;
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

function handleEvent(e) {
    switch (e.event) {
        case "post":
            postsSection.hidden = false;
            renderPost(e.data);
            break;
        case "image":
            imagesSection.hidden = false;
            renderImage(e.data, imagesEl);
            break;
        case "done":
            break;
        case "error":
            statusEl.textContent = `Error: ${e.data}`;
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

// Infinite scroll
const io = new IntersectionObserver(
    (entries) => {
        if (
            entries[0].isIntersecting &&
            !state.loading &&
            !state.done &&
            state.offset > 0
        ) {
            loadNext();
        }
    },
    { rootMargin: "300px" },
);
io.observe($("#sentinel"));
