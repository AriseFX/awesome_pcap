import Vue from 'vue'
import App from './App.vue'

import { Table, Tag, Alert } from 'ant-design-vue';
import 'ant-design-vue/dist/antd.css';
Vue.use(Table);
Vue.use(Tag);
Vue.use(Alert);
Vue.config.productionTip = false

new Vue({
  render: h => h(App),
}).$mount('#app')
