<script setup>
import { onBeforeMount, ref } from 'vue'
import { useRouter } from 'vue-router'
import { mdiMonitorCellphone, mdiTableBorder, mdiTableOff, mdiGithub, mdiPlus, mdiFaceAgent } from '@mdi/js'
import { useMainStore } from '@/stores/main'
import SectionMain from '@/components/SectionMain.vue'
import NotificationBar from '@/components/NotificationBar.vue'
import TableTickets from '@/components/TableTickets.vue'
import CardBox from '@/components/CardBox.vue'
import LayoutAuthenticated from '@/layouts/LayoutAuthenticated.vue'
import SectionTitleLineWithButton from '@/components/SectionTitleLineWithButton.vue'
import BaseButton from '@/components/BaseButton.vue'
import CardBoxNewClient from '@/components/CardBoxNewClient.vue'

const mainStore = useMainStore()

onBeforeMount(() => {
  mainStore.getTickets()
  // console.log('Clients below')
  // console.log(mainStore._clients)
  // mainStore._clients.forEach(client => {
  //   console.log(client.email);
  // });
})
const newTicket = () => {
  router.push('/support/new-ticket')
}
const router = useRouter()
const isModalActive = ref(false)

</script>

<template>
  <LayoutAuthenticated>
    
    <SectionMain>
      <SectionTitleLineWithButton :icon="mdiFaceAgent" title="Welcome to support portal" main>
        <BaseButton
          target="_blank"
          :icon="mdiPlus"
          label="New ticket"
          color="success"
          rounded-full
          small
          @click="newTicket"
        />
      </SectionTitleLineWithButton>

      <CardBox class="mb-6" has-table>
        <TableTickets checkable />
      </CardBox>
    </SectionMain>
  </LayoutAuthenticated>
</template>
