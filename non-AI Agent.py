class Agent:
	# Constructor, automatically called upon creation of new instances of the class, self refers to that new object
    def __init__(self, name):
        self.name = name

	# Conceptually the agent we have created watches its environment and stores what it sees
    def observe(self, state):
        self.state = state

    # The agent thinks using what it has observed
    def think(self):
        if self.state == "enemy_near":
            return "attack"
        return "explore"

    # It acts based upon the decision it makes while thinking
    def act(self, decision):
        print(f"{self.name} decides to {decision}")

agent = Agent("LeviBot")
agent.observe("enemy_near")
decision = agent.think()
agent.act(decision)