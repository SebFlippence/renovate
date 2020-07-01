import { GraphQLClient } from 'graphql-request';
import semver from 'semver';
import { RenovateConfig } from '../../../config';
import { logger } from '../../../logger';

global.fetch = require('node-fetch');

const graphQLClient = new GraphQLClient('https://api.github.com/graphql', {
  headers: {
    authorization: `Bearer ${process.env.GITHUB_COM_TOKEN}`,
  },
});

export const securityUpdatesOnly = async (
  flattenedUpdates: RenovateConfig[]
): Promise<RenovateConfig[]> => {
  const uniqueUpdates = new Map();
  flattenedUpdates
    .filter((u) => u.depName && u.depName.length)
    .forEach((u) => uniqueUpdates.set(u.depName, u));

  const queries = [];
  uniqueUpdates.forEach((value, key) => {
    const graphQLDepName = key.replace(/[^a-z]/g, '_');
    queries.push(`${graphQLDepName}: securityVulnerabilities(last: 1, package: "${key}", ecosystem: NPM, orderBy: {field: UPDATED_AT, direction: DESC}) {
        ...securityVulnerability
      }`);
  });

  const securityVulnerabilitiesRes = await graphQLClient.request(`fragment securityVulnerability on SecurityVulnerabilityConnection {
    totalCount
    edges {
      node {
        advisory {
          ghsaId
          publishedAt
          updatedAt
          severity
          summary
          description
          references {
            url
          }
        }
        vulnerableVersionRange
        firstPatchedVersion {
          identifier
        }
        package {
          ecosystem
          name
        }
      }
    }
  }

  {
    ${queries.join('\n')}
  }`);

  const securityVulnerabilities = new Map();
  Object.values(securityVulnerabilitiesRes)
    .filter((u: any) => u.totalCount >= 1)
    .forEach((u: any) => {
      const {
        package: pkg,
        firstPatchedVersion,
        vulnerableVersionRange,
        advisory,
      } = u.edges[0].node;

      securityVulnerabilities.set(pkg.name, {
        package: pkg.name,
        patchedIn: firstPatchedVersion.identifier,
        vulnerableVersionRange,
        ...advisory,
      });
    });

  const securityUpdates = flattenedUpdates.filter(
    (u: any) =>
      u.depName &&
      u.depName.length &&
      securityVulnerabilities.has(u.depName) &&
      (semver.lt(
        u.lockedVersion,
        securityVulnerabilities.get(u.depName).patchedIn
      ) ||
        logger.debug(securityVulnerabilities.get(u.depName)))
  );

  logger.debug(
    `${securityUpdates.length || 'no'} security vulnerability(s) found`
  );

  return securityUpdates;
};
