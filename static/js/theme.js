/*
 * Theme controller for Decompiler Explorer.
 *
 * Exposes window.DETheme with three responsibilities:
 *   1. Persist the user's preference ('light' | 'dark' | 'auto') in localStorage.
 *   2. Apply the resolved theme to <html data-bs-theme="..."> (Bootstrap 5.3+).
 *   3. Broadcast a 'de:themechange' event on document so other scripts
 *      (e.g. Ace editor setup) can react.
 *
 * A small inline script in <head> applies the stored theme before paint to
 * avoid a flash of incorrect theme; this file then wires up the toggle UI.
 */
(function () {
    'use strict';

    const STORAGE_KEY = 'de-theme';
    const VALID = ['light', 'dark', 'auto'];
    const ACE_THEMES = { light: 'ace/theme/chrome', dark: 'ace/theme/tomorrow_night' };

    const media = window.matchMedia('(prefers-color-scheme: dark)');

    function getStored() {
        const v = localStorage.getItem(STORAGE_KEY);
        return VALID.includes(v) ? v : 'auto';
    }

    function resolve(pref) {
        if (pref === 'auto') return media.matches ? 'dark' : 'light';
        return pref;
    }

    function apply(pref) {
        const effective = resolve(pref);
        document.documentElement.setAttribute('data-bs-theme', effective);
        document.documentElement.setAttribute('data-theme-pref', pref);
        document.dispatchEvent(new CustomEvent('de:themechange', {
            detail: { preference: pref, effective: effective }
        }));
    }

    function set(pref) {
        if (!VALID.includes(pref)) return;
        localStorage.setItem(STORAGE_KEY, pref);
        apply(pref);
        syncToggleUI(pref);
    }

    function syncToggleUI(pref) {
        document.querySelectorAll('[data-theme-value]').forEach(el => {
            const active = el.getAttribute('data-theme-value') === pref;
            el.classList.toggle('active', active);
            el.setAttribute('aria-pressed', active ? 'true' : 'false');
        });
        const icon = document.querySelector('[data-theme-icon]');
        if (icon) {
            const effective = resolve(pref);
            // fa-sun for light, fa-moon for dark, fa-circle-half-stroke for auto
            const cls = pref === 'auto'
                ? 'fa-solid fa-circle-half-stroke'
                : (effective === 'dark' ? 'fa-solid fa-moon' : 'fa-solid fa-sun');
            icon.className = cls;
            icon.setAttribute('aria-label', `Theme: ${pref}`);
        }
    }

    // Re-apply when OS theme changes, but only if user chose 'auto'.
    media.addEventListener('change', () => {
        if (getStored() === 'auto') apply('auto');
    });

    // Wire up clicks on any element with [data-theme-value="..."].
    document.addEventListener('click', (e) => {
        const trigger = e.target.closest('[data-theme-value]');
        if (!trigger) return;
        e.preventDefault();
        set(trigger.getAttribute('data-theme-value'));
    });

    // Initial UI sync once DOM is ready (pre-paint script already set data-bs-theme).
    document.addEventListener('DOMContentLoaded', () => syncToggleUI(getStored()));

    window.DETheme = {
        get preference() { return getStored(); },
        get effective() { return resolve(getStored()); },
        set: set,
        aceThemeFor: function (effective) { return ACE_THEMES[effective]; }
    };
})();
