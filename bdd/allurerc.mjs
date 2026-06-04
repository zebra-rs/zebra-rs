// Allure 3 report configuration.
//
// Each cucumber feature is run in its own instance and tee'd to a separate
// `allure-results/results-<pid>-<feature>.json` file (see tests/cucumber.rs).
// Allure 3's cucumber-json reader, however, only tags each scenario with a
// `feature` label (the `Feature:` name) and `tag` labels — it never emits the
// `suite`/`parentSuite` labels that the report's tree groups on by default.
// With no suite labels and no titlePath, the awesome plugin falls back to
// `groupBy: []`, which dumps every scenario flat at the root, so all features
// look merged into one undifferentiated list.
//
// Grouping the tree by the `feature` label restores one collapsible group per
// feature file, which is what we want when running a whole suite (e.g. `make
// isis`) and browsing the report feature-by-feature.
export default {
  plugins: {
    awesome: {
      options: {
        groupBy: ["feature"],
      },
    },
  },
};
