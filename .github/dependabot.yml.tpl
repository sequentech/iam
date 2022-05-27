version: 2
updates:
{% for branch in branches %}
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "daily"
    target-branch: "{{ branch }}"
    # Disable version updates for npm dependencies, only enabling security
    # updates. See 
    # https://docs.github.com/en/code-security/dependabot/dependabot-security-updates/configuring-dependabot-security-updates#overriding-the-default-behavior-with-a-configuration-file
    open-pull-requests-limit: 0

{% endfor %}