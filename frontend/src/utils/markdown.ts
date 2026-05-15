/**
 * Lightweight markdown -> HTML converter for inline rendering of LLM
 * output in the UI. Handles the subset of markdown the agent actually
 * emits across the app:
 *
 *   `**bold**`     -> <b>bold</b>        (CommonMark double-asterisk)
 *   `*bold*`       -> <b>bold</b>        (Telegram legacy single-asterisk)
 *   `_italic_`     -> <i>italic</i>      (underscore italic)
 *   `#+ heading`   -> <b>heading</b>     (leading markdown heading -> bold,
 *                                         since headings inside cards look
 *                                         out of place visually)
 *
 * Input is HTML-escaped first so user-controlled strings can't inject
 * tags. Output is meant for `dangerouslySetInnerHTML`.
 *
 * The regex for `*bold*` excludes positions adjacent to another `*` so
 * it doesn't double-handle content already normalized by the `**` rule.
 * The regex for `_italic_` requires the underscore to be at a word
 * boundary so identifiers like `snake_case` survive untouched.
 */
export function renderMd(text: string): string {
  let safe = text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");

  // Leading `#+ heading` -> bold (run line-by-line via /gm).
  safe = safe.replace(/^\s*(#{1,6})\s+(.+)$/gm, "<b>$2</b>");

  // **bold**
  safe = safe.replace(/\*\*([^*\n]+?)\*\*/g, "<b>$1</b>");

  // *bold* — only when neither neighbour is another `*` (skip the `**`
  // residue and avoid matching arithmetic-looking `*`).
  safe = safe.replace(
    /(?<!\*)\*(?!\*)([^*\n]+?)(?<!\*)\*(?!\*)/g,
    "<b>$1</b>",
  );

  // _italic_ — only when the underscore sits at a word boundary, so
  // identifiers and file paths (snake_case, /var/run/foo_bar) are left
  // alone.
  safe = safe.replace(
    /(?<![\w_])_([^_\n]+?)_(?![\w_])/g,
    "<i>$1</i>",
  );

  return safe;
}
