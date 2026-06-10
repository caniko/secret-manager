{lib, ...}: {
  services.secretSync = {
    enable = true;
    targets = {
      "ci-token" = {
        secret = "age/secrets/ci-token.age";
        name = "CI_TOKEN";
        codeberg = ["caniko/my-repo"];
      };
      "deploy-key" = {
        secret = "age/secrets/deploy-key.age";
        name = "DEPLOY_KEY";
        codeberg = ["caniko/my-repo" "caniko/other-repo"];
        github = ["caniko/mirror-repo"];
      };
    };
  };
}
