{lib, ...}: {
  services.secretSync = {
    enable = true;
    targets = {
      "api-key" = {
        secret = "age/secrets/api-key.age";
        name = "API_KEY";
        codeberg = ["caniko/api-repo"];
        host = "git.example.com";
      };
    };
  };
}
