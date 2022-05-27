version: 2
updates:
{% for branch in branches %}
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "daily"
    target-branch: "{{ branch }}"

{% endfor %}