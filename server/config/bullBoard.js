// Bull Board setup (optional admin UI for queue monitoring)
const createBullBoard = () => {
  // Can be extended with @bull-board/express for queue monitoring UI
  console.log('[BullBoard] Queue monitoring initialized');
};

module.exports = { createBullBoard };
