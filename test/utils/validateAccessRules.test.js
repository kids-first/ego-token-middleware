// Necessary to polyfill Babel (replaces @babel/polyfill since 7.4.0)
// see https://babeljs.io/docs/en/7.4.0/babel-polyfill
import 'core-js/stable';
import 'regenerator-runtime/runtime';

import { validateAccessRules } from '../../src/utils';

describe('validateAccessRules', () => {
  describe('ruleSetOne', () => {
    const UNAUTHORIZED = { code: 401, message: 'unauthorized' };
    const FORBIDDEN = { code: 403, message: 'forbidden' };
    const ruleSetOne = [
      {
        type: 'allow',
        route: ['/', '/(.*)'],
        role: 'admin',
      },
      {
        type: 'deny',
        route: ['/', '/(.*)'],
        role: ['user'],
      },
      {
        type: 'allow',
        route: [`/(.*)/graphql`, `/(.*)/graphql/(.*)`, `/(.*)/download`],
        status: ['approved'],
        role: 'user',
      },
      {
        type: 'allow',
        route: [`/(.*)/ping`],
        tokenExempt: true,
      },
    ];

    test('deny root from role', () =>
      expect(
        validateAccessRules({
          url: '/',
          user: { roles: ['user'] },
          accessRules: ruleSetOne,
        }),
      ).toEqual(FORBIDDEN));

    test('deny non-root from role', () =>
      expect(
        validateAccessRules({
          url: '/abcd',
          user: { roles: ['user'] },
          accessRules: ruleSetOne,
        }),
      ).toEqual(FORBIDDEN));

    test('deny non-root from status', () =>
      expect(
        validateAccessRules({
          url: '/a/graphql',
          user: { roles: ['user'], status: 'pending' },
          accessRules: ruleSetOne,
        }),
      ).toEqual(FORBIDDEN));

    test('when user is not yet approved', () =>
      expect(
        validateAccessRules({
          url: '/a/graphql',
          user: { roles: ['user'], status: 'pending' },
          accessRules: ruleSetOne,
          valid: false,
        }),
      ).toEqual(FORBIDDEN));

    test('allow non-root from status', () =>
      expect(
        validateAccessRules({
          url: '/a/graphql',
          user: { roles: ['user'], status: 'approved' },
          accessRules: ruleSetOne,
          valid: true,
        }),
      ).toEqual(0));

    test('when token is invalid', () =>
      expect(
        validateAccessRules({
          url: '/a/graphql',
          user: { roles: ['user'], status: 'approved' },
          accessRules: ruleSetOne,
          valid: false,
        }),
      ).toEqual(UNAUTHORIZED));

    test('allow non-root from status with gql extension', () =>
      expect(
        validateAccessRules({
          url: '/a/graphql/abcd',
          user: { roles: ['user'], status: 'approved' },
          accessRules: ruleSetOne,
          valid: true,
        }),
      ).toEqual(0));

    test('allow non-root from status with wildcard', () =>
      expect(
        validateAccessRules({
          url: '/fdlkj/download',
          user: { roles: ['USER'], status: 'Approved' },
          accessRules: ruleSetOne,
          valid: true,
        }),
      ).toEqual(0));

    test('allow root from role', () =>
      expect(
        validateAccessRules({
          url: '/',
          user: { roles: ['admin'], status: 'rejected' },
          accessRules: ruleSetOne,
          valid: true,
        }),
      ).toEqual(0));

    test('allow non-root from role', () =>
      expect(
        validateAccessRules({
          url: '/asfdk',
          user: { roles: ['admin'], status: 'rejected' },
          accessRules: ruleSetOne,
          valid: true,
        }),
      ).toEqual(0));

    test('ignore invalid token if tokenExempt', () =>
      expect(
        validateAccessRules({
          url: '/asd/ping',
          user: { roles: ['admin'], status: 'rejected' },
          accessRules: ruleSetOne,
          valid: false,
        }),
      ).toEqual(0));
  });
});
