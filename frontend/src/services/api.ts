import axios from 'axios'
import type { Threat, Action, SystemStatus, ComplianceReport } from '../types'

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
})

export const threatService = {
  getAll: async (limit = 50): Promise<Threat[]> => {
    const response = await api.get('/api/v1/threats', { params: { limit } })
    return response.data.threats || []
  },

  getById: async (id: string): Promise<Threat> => {
    const response = await api.get(`/api/v1/threats/${id}`)
    return response.data
  },

  analyze: async (log: any): Promise<Threat> => {
    const response = await api.post('/api/v1/analyze', log)
    return response.data
  },
}

export const actionService = {
  getPending: async (): Promise<Action[]> => {
    const response = await api.get('/api/v1/actions/pending')
    return response.data.actions || []
  },

  getHistory: async (limit = 50): Promise<Action[]> => {
    const response = await api.get('/api/v1/actions/history', { params: { limit } })
    return response.data.actions || []
  },

  getById: async (id: string): Promise<Action> => {
    const response = await api.get(`/api/v1/actions/${id}`)
    return response.data.action
  },

  approve: async (id: string, approver: string, reason?: string): Promise<any> => {
    const response = await api.post(`/api/v1/actions/${id}/approve`, {
      approver,
      reason,
    })
    return response.data
  },

  reject: async (id: string, approver: string, reason?: string): Promise<any> => {
    const response = await api.post(`/api/v1/actions/${id}/reject`, {
      approver,
      reason,
    })
    return response.data
  },

  rollback: async (id: string, reason?: string): Promise<any> => {
    const response = await api.post(`/api/v1/actions/${id}/rollback`, {
      reason,
    })
    return response.data
  },
}

export const systemService = {
  getStatus: async (): Promise<SystemStatus> => {
    const response = await api.get('/api/v1/system/status')
    return response.data
  },

  getHealth: async (): Promise<any> => {
    const response = await api.get('/health')
    return response.data
  },
}

export const complianceService = {
  generateReport: async (
    type: string,
    startDate: string,
    endDate: string
  ): Promise<ComplianceReport> => {
    const response = await api.post('/api/v1/compliance/reports', {
      type,
      period_start: startDate,
      period_end: endDate,
    })
    return response.data
  },

  getReports: async (): Promise<ComplianceReport[]> => {
    const response = await api.get('/api/v1/compliance/reports')
    return response.data.reports || []
  },

  getReportById: async (id: string): Promise<ComplianceReport> => {
    const response = await api.get(`/api/v1/compliance/reports/${id}`)
    return response.data
  },
}

export default api


