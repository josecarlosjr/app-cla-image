/**
 * Visual theme switching.
 *
 * The app was built dark-first with hardcoded Tailwind slate classes
 * (`bg-slate-900`, `text-slate-100`, ...) spread across ~15 component
 * files. Rewriting every component to use `dark:` variants would be a
 * huge, risky change. Instead, index.css remaps the slate utilities the
 * app actually uses to CSS custom properties, and a class on <html>
 * swaps the property values. The default (dark) values are exactly the
 * original slate colors, so dark mode is pixel-identical to before and
 * components never had to change.
 *
 * This module owns: the theme catalogue, persistence (localStorage),
 * and the <html> class toggle.
 */

export type ThemeId = "dark" | "light" | "sepia";

export const THEMES: {
  id: ThemeId;
  label: string;
  description: string;
  // Three-colour preview swatch shown in the Settings picker so the
  // user can see roughly what they're choosing before applying.
  swatch: { bg: string; surface: string; text: string };
}[] = [
  {
    id: "dark",
    label: "Escuro",
    description: "Padrao. Fundo escuro, baixo brilho.",
    swatch: { bg: "#020617", surface: "#0f172a", text: "#f1f5f9" },
  },
  {
    id: "light",
    label: "Claro",
    description: "Fundo branco, alto contraste.",
    swatch: { bg: "#f1f5f9", surface: "#ffffff", text: "#0f172a" },
  },
  {
    id: "sepia",
    label: "Sepia",
    description: "Tom quente, suave para leitura prolongada.",
    swatch: { bg: "#efe5d0", surface: "#f7efdd", text: "#3b2f1c" },
  },
];

const STORAGE_KEY = "pia-theme";

export function getStoredTheme(): ThemeId {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    if (v === "light" || v === "sepia" || v === "dark") return v;
  } catch {
    /* storage disabled (private mode) — fall through to default */
  }
  return "dark";
}

export function applyTheme(theme: ThemeId): void {
  const el = document.documentElement;
  el.classList.remove("theme-light", "theme-sepia");
  if (theme === "light") el.classList.add("theme-light");
  else if (theme === "sepia") el.classList.add("theme-sepia");
  // theme === "dark" -> no class -> :root defaults (the original slate
  // palette) apply.
  try {
    localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    /* session-only theme is fine if storage is unavailable */
  }
}
