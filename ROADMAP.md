# Roadmap

## Completed

### Core Features
- [x] WebSocket real-time communication
- [x] Channel creation with custom ID (letters & numbers, 2-32 chars)
- [x] Channel password protection
- [x] Random channel ID generation
- [x] URL forwarding with 10s expiration
- [x] Remaining time countdown (adjusted for latency)
- [x] End-to-end latency display

### Producer
- [x] Camera access and QR code scanning (jsQR)
- [x] Event-driven URL sending (only on change)
- [x] Consumer count display
- [x] Share link with copy button

### Consumer
- [x] Join channel by ID + password
- [x] Real-time URL reception
- [x] Countdown timer
- [x] Open URL button

### Admin & Infrastructure
- [x] Admin panel (hidden from nav, accessible via /admin.html)
- [x] Custom domain configuration for share links
- [x] Active channels overview
- [x] HTTPS support (self-signed certificates)
- [x] Docker & docker-compose support

---

## Pending

### User System
- [ ] User registration & login
- [ ] User ID and password authentication
- [ ] User profile (customized bios)
- [ ] User contribution count

### Statistics
- [ ] Total number of users
- [ ] Number of live users
- [ ] Number of live Producers
- [ ] Leaderboard

### Logging
- [ ] Record URL with timestamp
- [ ] Record user login IP and time
- [ ] Account abuse detection

### Database
- [ ] SQLite integration for persistence
- [ ] User data storage
- [ ] URL history storage

### Other
- [ ] Fetch standard time for Producer
- [ ] Privacy policy page
- [ ] Cloudflare Worker compatibility

### Future Considerations
- [ ] Hall (marketplace for Producers and Consumers) - *low priority*
