<template>
  <div id="app">
    <a-table :columns="columns" :data-source="data" rowKey="id">
      <span slot="dup_count" slot-scope="dup_count">
        <a-tag
          :key="dup_count"
          :color="
            dup_count === 0 ? 'green' : dup_count < 5 ? 'geekblue' : 'red'
          "
        >
          {{ dup_count }}
        </a-tag>
      </span>
    </a-table>
  </div>
</template>

<script>
import data from "./data.js";
window._data = data.data;
const columns = [
  {
    title: "No",
    dataIndex: "id",
    key: "id",
  },
  {
    title: "Source",
    dataIndex: "ipvnhdr.saddr",
    key: "ipvnhdr.saddr",
  },
  {
    title: "Destination",
    dataIndex: "ipvnhdr.daddr",
    key: "ipvnhdr.daddr",
  },
  {
    title: "Protocol",
    dataIndex: "protocol",
    key: "protocol",
  },
  {
    title: "len",
    dataIndex: "len",
    key: "len",
  },
  {
    title: "frame 重传次数,丢包概率",
    dataIndex: "dup_count",
    key: "dup_count",
    scopedSlots: { customRender: "dup_count" },
  },
];
export default {
  name: "App",
  data() {
    console.log(window._data);
    return {
      data: window._data.data,
      columns,
    };
  },
};
</script>

<style>
#app {
  font-family: Avenir, Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-align: center;
  color: #2c3e50;
  margin-top: 60px;
}
</style>
