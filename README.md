# Enduroworx Plettenberg Bay — Workshop Job Board

Live job sheets for the workshop: customers book bikes in and follow progress on their phones, Erik manages every job, and the workshop TV shows all open jobs.

- `index.html` — the whole app (customer view, staff view, TV board). Settings are at the top of the script: `FIREBASE_CONFIG`, `STAFF`, `SMS_LOGIN`.
- `firestore.rules` — paste into Firebase → Firestore → Rules. Keep `staffList()` in step with `STAFF` in `index.html`.

TV board: in the app, staff tap **TV screens → + New screen link** and use that link in the signage app.
