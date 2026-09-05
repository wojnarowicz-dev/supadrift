'use strict';

// Punkt wejscia dla uzycia jako biblioteka. Wiersz polecen jest w bin/supadrift.js.

module.exports = {
  ...require('./tokenizer'),
  ...require('./signature'),
  ...require('./expected'),
  ...require('./introspect'),
  ...require('./compare'),
  ...require('./report'),
  secrets: require('./secrets'),
  readonly: require('./db/readonly'),
  drivers: {
    pg: require('./db/pg'),
    cli: require('./db/cli'),
  },
};
