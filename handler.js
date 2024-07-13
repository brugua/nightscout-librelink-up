const { main } = require('./dist/index');

exports.main = async (event) => {
  return await main(event);
};