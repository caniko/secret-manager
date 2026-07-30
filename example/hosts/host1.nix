{lib, ...}: {
  services.secretSync = {
    enable = true;
    targets = {
      "ci-token" = {
        secret = "age/secrets/ci-token.age";
        name = "CI_TOKEN";
        codeberg = ["caniko/my-repo"];
        codefloe = ["caniko/my-repo"];
        github = ["caniko/my-repo"];
      };
      "deploy-key" = {
        secret = "age/secrets/deploy-key.age";
        name = "DEPLOY_KEY";
        codeberg = ["caniko/my-repo" "caniko/other-repo"];
        codebergOrgs = ["caniko"];
      };
      "public-key" = {
        source = "age/secrets/public-key.asc";
        name = "PUBLIC_KEY";
        codeberg = ["caniko/my-repo"];
        codebergOrgs = ["caniko"];
        codebergUser = true;
      };
    };
  };
}
