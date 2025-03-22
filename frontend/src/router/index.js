import { createRouter, createWebHistory } from 'vue-router'
import Home from '../views/Home.vue'

const routes = [
  {
    path: '/',
    name: 'Home',
    component: Home
  },
  {
    path: '/cve-list',
    name: 'CVEList',
    component: () => import('../views/CVEList.vue')
  },
  {
    path: '/analysis',
    name: 'Analysis',
    component: () => import('../views/DataAnalysis.vue')
  },

  {
    path: '/cve/:id',
    name: 'CVEDetail',
    component: () => import('../views/CVEDetail.vue')
  }
  
]

const router = createRouter({
  history: createWebHistory(process.env.BASE_URL),
  routes
})

export default router
