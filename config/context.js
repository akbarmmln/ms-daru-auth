const { AsyncLocalStorage } = require('async_hooks');

const asyncLocalStorage = new AsyncLocalStorage();
const uuidGen = require('uuid');

const integrationGenerateContext = (req, res, next) => {
  asyncLocalStorage.run(new Map(), () => {
    const uuid = uuidGen.v4();
    asyncLocalStorage.getStore().set('context', { 'x-request-id': uuid });
    next();
  });
};

module.exports = {
  asyncLocalStorage,
  integrationGenerateContext,
};
