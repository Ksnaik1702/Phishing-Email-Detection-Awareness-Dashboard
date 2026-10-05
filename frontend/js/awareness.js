/**
 * FILE NAME: awareness.js
 * PURPOSE: Security Awareness & Training View Controller.
 *          Renders interactive checklist and micro-learning modules.
 */

async function loadAwareness() {
  try {
    const data = await API.getAwarenessData();
    renderChecklist(data.checklist || []);
    renderMicroLessons(data.micro_lessons || []);
  } catch (err) {
    console.error("Awareness load error:", err);
  }
}

function renderChecklist(checklistItems) {
  const container = document.getElementById("checklist-container");
  if (!container) return;
  container.innerHTML = "";

  checklistItems.forEach((item, idx) => {
    const div = document.createElement("label");
    div.className = "flex items-start gap-3 p-3 rounded-lg bg-slate-900 border border-cyberBorder hover:border-emerald-500/50 cursor-pointer transition";
    div.innerHTML = `
      <input type="checkbox" class="mt-1 w-4 h-4 text-emerald-500 rounded border-slate-700 bg-slate-800 focus:ring-emerald-500 focus:ring-offset-0">
      <span class="text-xs text-slate-300 select-none">${escapeHtml(item)}</span>
    `;
    container.appendChild(div);
  });
}

function renderMicroLessons(lessons) {
  const grid = document.getElementById("lessons-grid");
  if (!grid) return;
  grid.innerHTML = "";

  lessons.forEach((l, idx) => {
    const card = document.createElement("div");
    card.className = "bg-cyberCard border border-cyberBorder rounded-xl p-5 space-y-3 hover:border-blue-500/40 transition flex flex-col justify-between";
    card.innerHTML = `
      <div class="space-y-2">
        <div class="flex items-center justify-between">
          <span class="text-[10px] uppercase font-bold text-blue-400 bg-blue-500/10 px-2 py-0.5 rounded border border-blue-500/20">Lesson #${idx + 1}</span>
          <span class="text-[10px] text-slate-500"><i class="fa-solid fa-stopwatch mr-1"></i>${escapeHtml(l.duration)}</span>
        </div>
        <h4 class="text-sm font-bold text-white">${escapeHtml(l.title)}</h4>
        <p class="text-xs text-slate-300 leading-relaxed">${escapeHtml(l.content)}</p>
      </div>
      <div class="pt-2 border-t border-cyberBorder/60 flex items-center justify-between text-[11px] text-slate-400">
        <span class="text-emerald-400"><i class="fa-solid fa-shield-check mr-1"></i> Defensive Skill</span>
        <button onclick="markLessonCompleted(this)" class="text-blue-400 hover:text-blue-300 font-medium">Mark Read ✓</button>
      </div>
    `;
    grid.appendChild(card);
  });
}

function markLessonCompleted(btn) {
  btn.textContent = "Completed ✓";
  btn.classList.remove("text-blue-400", "hover:text-blue-300");
  btn.classList.add("text-emerald-400", "font-bold");
  btn.disabled = true;
}
