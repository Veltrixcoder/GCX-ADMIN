### 3. Endpoints and Data Model Changes

#### /api/register
- Registers a new user in the `users` collection.
- Returns `{ id: <ObjectId>, name, email }` in the response.

#### /api/login
- Authenticates user by email and password from MongoDB.
- Returns `{ id: <ObjectId>, name, email }` in the response.

#### /api/gift-cards
- Submits a gift card entry to the `submissions` collection.
- `user_id` is now stored as an ObjectId, but accepts both ObjectId string and legacy numeric ID for compatibility.

#### /api/user-submissions/:userId
- Fetches submissions for a user.
- Accepts both ObjectId string and legacy numeric ID for `userId`.

#### /api/messages (POST)
- Sends a message for a user.
- Accepts both ObjectId string and legacy numeric ID for `userId`.
- Response includes `user_id`, `id`, and `_id` for compatibility.

#### /api/messages/:userId (GET)
- Fetches messages for a user.
- Accepts both ObjectId string and legacy numeric ID for `userId`.

#### /api/admin/users, /api/admin/messages, /api/admin/submissions
- All admin endpoints now use MongoDB queries.
- Deletion and lookup endpoints accept both ObjectId and legacy numeric IDs where relevant.

### 4. Response Structure
- All endpoints that return user or message objects now include both `id` (legacy) and `_id` (MongoDB) fields where possible.
- This ensures compatibility with old clients expecting numeric IDs.

### 5. Other Notes
- The server no longer uses `.env` or `dotenv` for configuration; all credentials and ports are hardcoded.
- The server port has changed from 3000 to 7860.
- MongoDB connection uses the recommended `ServerApiVersion` and logs connection status.

---

**If you are updating a client or frontend:**
- Always use the `id` returned from login/register as `userId` in all requests.
- Both old numeric IDs and new ObjectId strings are supported for a smooth transition. 