<template>
  <div id="app">
    <a-table :columns="columns" :data-source="data" rowKey="id">
      <p slot="expandedRowRender" slot-scope="record" style="margin: 0">
        <!-- {{ record.next_frames }} -->
        <a-table
          :columns="frame_queue"
          :data-source="record.next_frames"
          rowKey="id"
        >
          <span slot="dup_count" slot-scope="dup_count">
            <a-tag
              :key="dup_count"
              :color="
                dup_count === 0 ? 'green' : dup_count < 5 ? 'geekblue' : 'red'
              "
            >
              {{ dup_count }}
            </a-tag>
          </span></a-table
        >
      </p>
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
      <span slot="dup_main_count" slot-scope="dup_main_count">
        <a-tag
          :key="dup_main_count"
          :color="
            dup_main_count === 0
              ? 'green'
              : dup_main_count < 5
              ? 'geekblue'
              : 'red'
          "
        >
          {{ dup_main_count }}
        </a-tag>
      </span>
      <span slot="quality" slot-scope="quality" style="white-space: pre-line">
        <a-tag
          :key="quality.quality + quality.quality_reason"
          :color="
            quality.quality === '高'
              ? 'green'
              : quality.quality === '中'
              ? 'geekblue'
              : 'red'
          "
        >
          {{ quality.quality }}
        </a-tag>
        <br />
        <a-alert
          :message="item"
          type="info"
          v-for="item in quality.quality_reason"
          :key="item"
        >
          {{ item }}
        </a-alert>
      </span>
    </a-table>
  </div>
</template>

<script>
// window._data = data.data;

for (let i of window._data.data) {
  let quality = {
    quality: "高",
    quality_reason: [],
  };
  if (i.dup_main_count > 5) {
    quality.quality = "低";
    quality.quality_reason.push("TCP 重传超过 5 次");
  } else {
    if (i.dup_main_count > 0) {
      quality.quality = "中";
      quality.quality_reason.push("有 TCP 重传现象");
    }
    if (i.next_frames.length < 6) {
      quality.quality = "低";
      quality.quality_reason.push("TCP 包少于 6 ,需要确认 tcp 完整性");
    }
    if (i.rst) {
      quality.quality = "低";
      quality.quality_reason.push("RST 发生");
      break;
    } else {
      for (let each of i.next_frames) {
        if (each.rst) {
          quality.quality = "低";
          quality.quality_reason.push("RST 发生");
          break;
        }
      }
    }
  }
  i.quality = quality;
}
const base = [
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
    title: "len",
    dataIndex: "len",
    key: "len",
  },
  {
    title: "seq",
    dataIndex: "seq",
    key: "seq",
  },
  {
    title: "ack_seq",
    dataIndex: "ack_seq",
    key: "ack_seq",
  },
  {
    title: "tcp 重传次数",
    dataIndex: "dup_count",
    key: "dup_count",
    scopedSlots: { customRender: "dup_count" },
  },
  {
    title: "flags",
    key: "flags",
    customRender: (e) => {
      let result = [];
      if (e.syn) {
        result.push("SYN");
      }
      if (e.fin) {
        result.push("FIN");
      }
      if (e.ack) {
        result.push("ACK");
      }
      if (e.psh) {
        result.push("PSH");
      }
      if (e.rst) {
        result.push("RST");
      }
      return result.join(" , ");
    },
  },
];
const columns = base.concat([
  {
    title: "Protocol",
    dataIndex: "protocol",
    key: "protocol",
  },
  {
    title: "message",
    dataIndex: "print_message",
    key: "print_message",
  },
  {
    title: "tcp 重传次数(总)",
    dataIndex: "dup_main_count",
    key: "dup_main_count",
    scopedSlots: { customRender: "dup_main_count" },
  },
  {
    title: "tcp 质量",
    key: "quality",
    dataIndex: "quality",
    scopedSlots: { customRender: "quality" },
  },
]);

const frame_queue = base.concat([]);
export default {
  name: "App",
  data() {
    return {
      data: window._data.data,
      columns,
      frame_queue,
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
