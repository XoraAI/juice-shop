import { type Request, type Response } from 'express'
import { WebSocketProvider, Contract, verifyMessage } from 'ethers'

import * as challengeUtils from '../lib/challengeUtils'
import { nftABI } from '../data/static/contractABIs'
import { challenges } from '../data/datacache'
import * as utils from '../lib/utils'

const nftAddress = '0x41427790c94E7a592B17ad694eD9c06A02bb9C39'
const addressesMinted = new Set()
let isEventListenerCreated = false

export function nftMintListener () {
  return async (req: Request, res: Response) => {
    try {
      const provider = new WebSocketProvider('wss://eth-sepolia.g.alchemy.com/v2/FZDapFZSs1l6yhHW4VnQqsi18qSd-3GJ')
      const contract = new Contract(nftAddress, nftABI, provider)
      if (!isEventListenerCreated) {
        void contract.on('NFTMinted', (minter: string) => {
          if (!addressesMinted.has(minter)) {
            addressesMinted.add(minter)
          }
        })
        isEventListenerCreated = true
      }
      res.status(200).json({ success: true, message: 'Event Listener Created' })
    } catch (error) {
      res.status(500).json(utils.getErrorMessage(error))
    }
  }
}

export function walletNFTVerify () {
  return (req: Request, res: Response) => {
    try {
      const metamaskAddress = req.body.walletAddress
      const message = req.body.message
      const signature = req.body.signature
      if (!metamaskAddress || !message || !signature) {
        res.status(400).json({ success: false, message: 'walletAddress, message and signature are required' })
        return
      }
      // Require proof that the caller controls the claimed wallet by verifying a
      // signature over the provided message. Without this, the public minter
      // address from on-chain NFTMinted events could be replayed by anyone.
      let recoveredAddress: string
      try {
        recoveredAddress = verifyMessage(message, signature)
      } catch {
        res.status(401).json({ success: false, message: 'Invalid wallet signature' })
        return
      }
      if (recoveredAddress.toLowerCase() !== String(metamaskAddress).toLowerCase()) {
        res.status(401).json({ success: false, message: 'Wallet signature does not match the provided address' })
        return
      }
      if (addressesMinted.has(metamaskAddress)) {
        addressesMinted.delete(metamaskAddress)
        challengeUtils.solveIf(challenges.nftMintChallenge, () => true)
        res.status(200).json({ success: true, message: 'Challenge successfully solved', status: challenges.nftMintChallenge })
      } else {
        res.status(200).json({ success: false, message: 'Wallet did not mint the NFT', status: challenges.nftMintChallenge })
      }
    } catch (error) {
      res.status(500).json(utils.getErrorMessage(error))
    }
  }
}
