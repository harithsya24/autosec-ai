# AutoSec AI Dashboard

Enterprise-ready React dashboard for real-time threat detection and autonomous mitigation.

## Features

- 🚨 **Real-Time Threat Stream** - Live updates via WebSocket
- 📊 **Analytics Dashboard** - Threat statistics and trends
- ⚡ **Action Management** - Approve/reject/rollback security actions
- 📋 **Compliance Reporting** - Automated SOC2/GDPR/HIPAA reports
- 🎨 **Modern UI** - Built with React, TypeScript, and Tailwind CSS

## Getting Started

### Prerequisites

- Node.js 18+ and npm
- Backend API running on `http://localhost:8000`

### Installation

```bash
cd frontend
npm install
```

### Development

```bash
npm run dev
```

The dashboard will be available at `http://localhost:3000`

### Build for Production

```bash
npm run build
npm run preview
```

## Project Structure

```
frontend/
├── src/
│   ├── components/      # Reusable UI components
│   ├── pages/          # Page components
│   ├── services/       # API and WebSocket services
│   ├── types/          # TypeScript type definitions
│   └── App.tsx         # Main app component
├── public/            # Static assets
└── package.json       # Dependencies
```

## Environment Variables

Create a `.env` file in the `frontend` directory:

```env
VITE_API_URL=http://localhost:8000
VITE_WS_URL=localhost:8000
```

## Features Overview

### Dashboard
- Real-time threat detection feed
- System status monitoring
- Quick stats overview

### Threat Detail
- Complete threat analysis
- AI reasoning chain
- RAG citations
- Confidence breakdown
- Action recommendations

### Actions
- Pending approvals
- Action history
- Approve/reject/rollback actions

### Analytics
- Threat statistics
- Trends over time
- Confidence distribution
- Threat type breakdown

### Compliance
- Generate compliance reports (SOC2, GDPR, HIPAA)
- Download reports
- View metrics and findings

## API Integration

The dashboard connects to the FastAPI backend:

- REST API: `/api/v1/*`
- WebSocket: `/ws`

## Technologies

- **React 18** - UI framework
- **TypeScript** - Type safety
- **Vite** - Build tool
- **Tailwind CSS** - Styling
- **Recharts** - Data visualization
- **React Router** - Navigation
- **Axios** - HTTP client

## Browser Support

- Chrome (latest)
- Firefox (latest)
- Safari (latest)
- Edge (latest)



