# Edgewood Claude Bridge

A small WordPress plugin that lets Claude Code manage Edgewood Community Church's Divi 5 site through the WordPress API.

- Works only for one WordPress user (`claude`) signed in with an Application Password.
- Can edit pages, posts and Divi library and theme builder items; can read and change Divi settings (license and API keys are hidden); can clear caches.
- Cannot run arbitrary code or database queries. Deletes go to the Trash.
- Every change is logged under Tools > Claude Bridge, which also has an on/off switch and a "Check for updates now" button.
- Updates come from this repository's releases and install when an administrator clicks "Update now".
