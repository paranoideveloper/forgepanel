import './bun-svelte-plugin';
import { GlobalWindow } from 'happy-dom';

const window = new GlobalWindow();

(globalThis as any).window = window;
(globalThis as any).document = window.document;
(globalThis as any).localStorage = window.localStorage;
(globalThis as any).navigator = window.navigator;
(globalThis as any).HTMLElement = window.HTMLElement;
(globalThis as any).Element = window.Element;
(globalThis as any).Node = window.Node;

if (!Element.prototype.animate) {
  Element.prototype.animate = function() {
    return {
      cancel: () => {},
      finish: () => {},
      play: () => {},
      pause: () => {},
      addEventListener: () => {},
      removeEventListener: () => {}
    } as any;
  };
}
