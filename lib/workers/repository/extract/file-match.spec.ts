import { RenovateConfig, platform } from '../../../../test/util';
import * as fileMatch from './file-match';

describe('workers/repository/extract/file-match', () => {
  const fileList = ['package.json', 'frontend/package.json'];
  describe('getIncludedFiles()', () => {
    it('returns fileList if no includePaths', () => {
      const res = fileMatch.getIncludedFiles(fileList, []);
      expect(res).toEqual(fileList);
    });
    it('returns exact matches', () => {
      const includePaths = ['frontend/package.json'];
      const res = fileMatch.getIncludedFiles(fileList, includePaths);
      expect(res).toMatchSnapshot();
      expect(res).toHaveLength(1);
    });
    it('returns minimatch matches', () => {
      const includePaths = ['frontend/**'];
      const res = fileMatch.getIncludedFiles(fileList, includePaths);
      expect(res).toMatchSnapshot();
      expect(res).toHaveLength(1);
    });
  });
  describe('filterIgnoredFiles()', () => {
    it('returns fileList if no ignoredPaths', () => {
      const res = fileMatch.filterIgnoredFiles(fileList, []);
      expect(res).toEqual(fileList);
    });
    it('ignores partial matches', () => {
      const ignoredPaths = ['frontend'];
      const res = fileMatch.filterIgnoredFiles(fileList, ignoredPaths);
      expect(res).toMatchSnapshot();
      expect(res).toHaveLength(1);
    });
    it('returns minimatch matches', () => {
      const ignoredPaths = ['frontend/**'];
      const res = fileMatch.filterIgnoredFiles(fileList, ignoredPaths);
      expect(res).toMatchSnapshot();
      expect(res).toHaveLength(1);
    });
  });
  describe('getMatchingFiles()', () => {
    const config: RenovateConfig = {
      includePaths: [],
      ignoredPaths: [],
      manager: 'npm',
      fileMatch: ['(^|/)package.json$'],
    };
    it('returns npm files', async () => {
      platform.getFileList.mockResolvedValue(fileList);
      fileList.push('Dockerfile');
      const res = await fileMatch.getMatchingFiles(config);
      expect(res).toMatchSnapshot();
      expect(res).toHaveLength(2);
    });
    it('deduplicates', async () => {
      platform.getFileList.mockResolvedValue(fileList);
      config.fileMatch.push('package.json');
      const res = await fileMatch.getMatchingFiles(config);
      expect(res).toMatchSnapshot();
      expect(res).toHaveLength(2);
    });
  });
});
