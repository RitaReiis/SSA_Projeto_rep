<script setup>
import { computed, ref } from 'vue'
import { useMainStore } from '@/stores/main'
import { mdiEye, mdiTrashCan } from '@mdi/js'
import CardBoxModal from '@/components/CardBoxModal.vue'
import BaseLevel from '@/components/BaseLevel.vue'
import BaseButtons from '@/components/BaseButtons.vue'
import BaseButton from '@/components/BaseButton.vue'
import PillTag from './PillTag.vue'
import axios from 'axios'
import { useRouter } from 'vue-router'

defineProps({
  checkable: Boolean
})

const mainStore = useMainStore()
const router = useRouter()
const items = computed(() => mainStore.tickets)

const isModalActive = ref(false)
const isModalDangerActive = ref(false)
const selectedTicketId = ref()
const ticketDescription = ref()
const ticketUserID = ref()
const ticketCategory = ref()
const ticketStatus = ref()
const ticketMessages = ref()
const textBoxPlaceholder = ref('Type your comment here...')
const currentPage = ref(0)
const remove = (arr, cb) => {
  const newArr = []

  arr.forEach((item) => {
    if (!cb(item)) {
      newArr.push(item)
    }
  })
  return newArr
}

const submitComment = async (ticketId, message) => {
  const submitCommentPayload = {
    message: message,
    user_id: localStorage.getItem('userId'),
    token: localStorage.getItem('token')
  }
  try {
    await axios.post(`http://localhost:5000/support/ticket/${ticketId}/new-message`, submitCommentPayload)
    isModalDangerActive.value = false
    ticketMessages.value.push({
      Username: localStorage.getItem('username'),
      MessageText: message
    })
    textBoxPlaceholder.value = ''
  } catch (error) {
    alert(`Error: ${error.message}`)
  }
}

function statusColer(status) {
  switch (status) {
    case 'resolved':
      return 'success';
    case 'Waiting for support':
      return 'warning';
    case 'Waiting for customer':
      return 'danger';
    case 'in progress':
      return 'info';
    default:
      return 'contrast';
  }
}
</script>

<template>
  <CardBoxModal v-model="isModalActive" :title="ticketDescription" updateOnDone="/support">
    <section class="modal-body">
      <div class="ticket-details">
        <p><strong>Requester (User ID):</strong> {{ ticketUserID }}</p>
        <p><strong>Category:</strong> {{ ticketCategory }}</p>
        <p><strong>Description:</strong> {{ ticketDescription }}</p>
        <p><strong>Status:</strong> {{ ticketStatus }}</p>
        <p><strong>Messages:</strong></p>
        <div class="messages-list" v-if="ticketMessages && ticketMessages.length">
          <ul>
            <li v-for="(msg, index) in ticketMessages" :key="index">
              <strong>{{ msg.Username }}:</strong> {{ msg.MessageText }}
            </li>
          </ul>
        </div>
        <p v-else>No messages available.</p>
      </div>
    </section>
    <footer class="modal-footer">
      <form @submit.prevent="submitComment(selectedTicketId, newComment)">
        <textarea v-model="newComment" rows="3" :placeholder="textBoxPlaceholder" required></textarea>
        <BaseButton label="Submit" color="info" type="submit" />
      </form>
    </footer>
  </CardBoxModal>

  <CardBoxModal v-model="isModalDangerActive" title="Please confirm" button="danger" has-cancel>
    <p>Are you sure you want to permanently delete client <b>User ID: {{ selectedClientId }}</b></p>
    <p>This is sample modal</p>
  </CardBoxModal>

  <table>
    <thead>
      <tr>
        <th>#</th>
        <th>Description</th>
        <th>Category</th>
        <th>Status</th>
        <th />
      </tr>
    </thead>
    <tbody>
      <tr v-for="ticket in items" :key="ticket['TicketID']">
        <td data-label="#">
          {{ ticket['TicketID'] }}
        </td>
        <td data-label="Description">
          {{ ticket['Description'] }}
        </td>
        <td data-label="Category">
          {{ ticket['Category'] }}
        </td>
        <td data-label="Status">
          <PillTag
            :color="statusColer(ticket['Status'])"
            :label="ticket['Status']"
            :small="true"
            :outline="false"
          />
          <!-- <span :class="statusBadgeClass(ticket['Status'])">
            {{ ticket['Status'] }}
          </span> -->
        </td>
        <td class="before:hidden lg:w-1 whitespace-nowrap">
          <BaseButtons type="justify-start lg:justify-end" no-wrap>
            <BaseButton color="info" :icon="mdiEye" small @click="() => {
                selectedTicketId = ticket['TicketID'];
                ticketUserID = ticket['UserID'];
                ticketDescription = ticket['Description'];
                ticketCategory = ticket['Category'];
                ticketStatus = ticket['Status'];
                ticketMessages = JSON.parse(ticket['Messages']);
                isModalActive = true
              }"
            />
          </BaseButtons>
        </td>
      </tr>
    </tbody>
  </table>
  <div class="p-3 lg:px-6 border-t border-gray-100 dark:border-slate-800">
    <BaseLevel>
      <BaseButtons>
        <BaseButton
          v-for="page in pagesList"
          :key="page"
          :active="page === currentPage"
          :label="page + 1"
          :color="page === currentPage ? 'lightDark' : 'whiteDark'"
          small
          @click="currentPage = page"
        />
      </BaseButtons>
      <small>Page {{ currentPageHuman }} of {{ numPages }}</small>
    </BaseLevel>
  </div>
</template>

<style scoped>
.status-badge {
  padding: 4px 8px;
  border-radius: 12px;
  color: white;
  font-weight: 600;
  font-size: 0.85em;
  display: inline-block;
  text-align: center;
}

.status-badge.resolved {
  background-color: #4caf50; /* green */
}

.status-badge.waiting-support {
  background-color: #ffc107; /* yellow */
  color: black;
}

.status-badge.waiting-customer {
  background-color: #f44336; /* red */
}

.status-badge.in-progress {
  background-color: #2196f3; /* blue */
}

.modal-body {
  padding: 20px;
  background-color: #f9f9f9;
  border-top: 1px solid #ddd;
}

.ticket-details p {
  margin: 10px 0;
  font-size: 1rem;
  color: #333;
}

.messages-list {
  margin-top: 10px;
  max-height: 200px;
  overflow-y: auto;
  border: 1px solid #ddd;
  padding: 10px;
  background-color: #fff;
  border-radius: 4px;
}

.messages-list ul {
  list-style-type: none;
  padding: 0;
}

.messages-list li {
  padding: 8px;
  margin-bottom: 5px;
  background-color: #eef1f7;
  border-radius: 4px;
  color: #555;
}

.modal-footer {
  padding: 15px 20px;
  border-top: 1px solid #ddd;
  display: flex;
  justify-content: flex-start;
  align-items: center;
  background-color: #f9f9f9;
}

.modal-footer textarea {
  width: 100%;
  resize: none;
  padding: 10px;
  border: 1px solid #ccc;
  border-radius: 4px;
  font-size: 0.95rem;
}

.modal-footer .BaseButton {
  margin-top: 10px;
  margin-left: 10px;
  font-size: 0.9rem;
  padding: 8px 20px;
}
</style>