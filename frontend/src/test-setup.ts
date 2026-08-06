if (typeof Element !== 'undefined' && !Element.prototype.animate) {
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
