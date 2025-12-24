<script setup>
import { reactive, ref } from 'vue'
import { mdiBallotOutline, mdiAccount, mdiMail, mdiGithub, mdiFlagOutline, mdiCancel, mdiCross, mdiClose, mdiFaceAgent } from '@mdi/js'
import SectionMain from '@/components/SectionMain.vue'
import CardBox from '@/components/CardBox.vue'
import FormCheckRadioGroup from '@/components/FormCheckRadioGroup.vue'
import FormFilePicker from '@/components/FormFilePicker.vue'
import FormField from '@/components/FormField.vue'
import FormControl from '@/components/FormControl.vue'
import BaseDivider from '@/components/BaseDivider.vue'
import BaseButton from '@/components/BaseButton.vue'
import BaseButtons from '@/components/BaseButtons.vue'
import SectionTitle from '@/components/SectionTitle.vue'
import LayoutAuthenticated from '@/layouts/LayoutAuthenticated.vue'
import SectionTitleLineWithButton from '@/components/SectionTitleLineWithButton.vue'
import NotificationBarInCard from '@/components/NotificationBarInCard.vue'
import axios from 'axios'
import { useRouter } from 'vue-router'

const router = useRouter()

const selectOptions = [
  { id: 1, label: 'Feature Request' },
  { id: 2, label: 'Technical Issue' },
  { id: 3, label: 'Billing' },
  { id: 4, label: 'Question' }
]

const form = reactive({
  title: '',
  category: '',
  description: ''
})

const customElementsForm = reactive({
  checkbox: ['lorem'],
  radio: 'one',
  switch: ['one'],
  file: null
})

const submit = () => {
  const newTicketPayload = {
    category: form.category['label'],
    status: "Waiting for support",
    description: form.description,
    user_id: localStorage.getItem('userId'),
    token: localStorage.getItem('token'),
    comp_id: localStorage.getItem('companyId')
  }

  axios
    .post('http://localhost:5000/support/new-ticket', newTicketPayload)
    .then((response) => {
      if (response.status >= 200 && response.status < 300) {
        alert('Ticket created successfully!');
        router.push('/support');
      } else {
        alert('Failed to create ticket. Please try again.');
      }
    })
    .catch((error) => {
      alert(error.message);
    });
}

const formStatusWithHeader = ref(true)

const formStatusCurrent = ref(0)

const formStatusOptions = ['info', 'success', 'danger', 'warning']

const formStatusSubmit = () => {
  formStatusCurrent.value = formStatusOptions[formStatusCurrent.value + 1]
    ? formStatusCurrent.value + 1
    : 0
}
</script>

<template>
  <LayoutAuthenticated>
    <SectionMain>
      <SectionTitleLineWithButton :icon="mdiFaceAgent" title="New Ticket" main>
        <BaseButton
          to="/company/employees/new"
          target="_blank"
          :icon="mdiClose"
          label=""
          color="danger"
          rounded-full
          small
        />
      </SectionTitleLineWithButton>
      <CardBox :class="cardClass" is-form @submit.prevent="submit">
        <FormField label="Category">
          <FormControl v-model="form.category" :options="selectOptions" />
        </FormField>
        <FormField label="Description">
          <FormControl type="textarea" placeholder="Describe your issue here" v-model="form.description"/>
        </FormField>
        <template #footer>
          <BaseButtons>
            <BaseButton type="submit" color="info" label="Submit" />
            <BaseButton type="reset" color="danger" outline label="Cancel" to="/company/employees" />
          </BaseButtons>
        </template>
      </CardBox>
    </SectionMain>
  </LayoutAuthenticated>
</template>
